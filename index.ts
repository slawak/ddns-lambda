import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsx from "@pulumi/awsx";
import * as awssdk from "aws-sdk";
import * as bcryptjs from "bcryptjs";
import * as _ from "lodash";
import { isIPv4, isIPv6 } from "net";
import { Validator } from "ip-num/Validator";
import { IPv6CidrRange } from "ip-num/IPRange";
import { IPv6 } from "ip-num/IPNumber";

const config = new pulumi.Config();

const zoneId = config.require("zoneid");
const domain = config.require("domain");
const ttl = parseInt(config.require("ttl"));
const user = config.require("user");
// get the hash in plaintext
const passhashsecret = config.requireSecret("passhash");

const updateDnsRole = new aws.iam.Role("update-dns-role", {
  assumeRolePolicy: JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      {
        Action: "sts:AssumeRole",
        Principal: {
          Service: "lambda.amazonaws.com",
        },
        Effect: "Allow",
        Sid: "",
      },
    ],
  }),
});

const updateDnsRolePolicy = new aws.iam.RolePolicy("update-dns-role-policy", {
  role: updateDnsRole,
  policy: JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      {
        Action: [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ],
        Effect: "Allow",
        Resource: "*",
      },
      {
        Action: [
          "route53:ListResourceRecordSets",
          "route53:ChangeResourceRecordSets",
        ],
        Effect: "Allow",
        Resource: `arn:aws:route53:::hostedzone/${zoneId}`,
      },
      {
        Action: ["route53:GetChange"],
        Effect: "Allow",
        Resource: "arn:aws:route53:::change/*",
      },
    ],
  }),
});

const checkQueryParams = (event: awsx.apigateway.Request) => {
  const hostname = event.queryStringParameters?.hostname;
  const ip = event.queryStringParameters?.ip;
  const ip6 = event.queryStringParameters?.ip6;
  const ip6lanprefix = event.queryStringParameters?.ip6lanprefix;

  if (!hostname)
    return {
      statusCode: 404,
      body: JSON.stringify({
        message: "parameter hostname required",
      }),
    };
  const hostnameRegex = `\\w+\\.${_.escapeRegExp(domain)}`;
  if (!hostname.match(hostnameRegex))
    return {
      statusCode: 404,
      body: JSON.stringify({
        message: "parameter hostname malformed",
      }),
    };
  if (ip && !isIPv4(ip))
    return {
      statusCode: 404,
      body: JSON.stringify({
        message: "parameter ip malformed",
      }),
    };
  if (ip6 && !isIPv6(ip6))
    return {
      statusCode: 404,
      body: JSON.stringify({
        message: "parameter ip6 malformed",
      }),
    };
  if (ip6lanprefix && !Validator.isValidIPv6CidrRange(ip6lanprefix))
    return {
      statusCode: 404,
      body: JSON.stringify({
        message: "parameter ip6lanprefix malformed",
      }),
    };
  return {
    hostname: hostname,
    ip: ip,
    ip6: ip6,
    ip6lanprefix: ip6lanprefix,
  };
};

const handler = new aws.lambda.CallbackFunction("update-dns-lambda-callback", {
  role: updateDnsRole,
  callback: async (event: awsx.apigateway.Request) => {
    console.info(
      "QUERY STRING PARAMETERS\n" +
        JSON.stringify(event.queryStringParameters, null, 2)
    );

    const checkResult = checkQueryParams(event);
    if (checkResult.statusCode == 404) {
      return checkResult;
    }
    const hostname = checkResult.hostname as string;
    const ip = checkResult.ip;
    const ip6 = checkResult.ip6;
    const ip6lanprefix = checkResult.ip6lanprefix;
    const action = ip || ip6 || ip6lanprefix ? "UPDATE" : "GET";

    const route53 = new aws.sdk.Route53();

    var changeResults: Array<
      Promise<
        awssdk.Request<
          awssdk.Route53.ChangeResourceRecordSetsResponse,
          awssdk.AWSError
        >
      >
    > = [];

    if (ip || ip6) {
      const records = [
        { ip: ip, type: "A" },
        { ip: ip6, type: "AAAA" },
      ].filter((r) => r.ip);
      const changes = records.map((r) => {
        return {
          Action: "UPSERT",
          ResourceRecordSet: {
            Name: hostname,
            Type: r.type,
            TTL: ttl,
            ResourceRecords: [
              {
                Value: r.ip as string,
              },
            ],
          },
        };
      });
      console.info("CHANGED RECORD SET\n" + JSON.stringify(changes, null, 2));
      changeResults.push(
        route53
          .changeResourceRecordSets({
            HostedZoneId: zoneId,
            ChangeBatch: {
              Changes: changes,
            },
          })
          .promise()
          .then((resp) => {
            console.info("CHANGE INFO\n" + JSON.stringify(resp, null, 2));
            return resp;
          })
          .catch((error) => {
            console.error("CHANGE ERROR\n" + JSON.stringify(error, null, 2));
            return error;
          })
      );
    }

    if (ip6lanprefix) {
      const ipv6range = IPv6CidrRange.fromCidr(ip6lanprefix);
      const ipv6mask = ipv6range.cidrPrefix.toMask().value.not();
      const ipv6rangeFirst = ipv6range.getFirst().value;
      const changesPromise = route53
        .listResourceRecordSets({
          HostedZoneId: zoneId,
        })
        .promise()
        .then((resp) =>
          resp.ResourceRecordSets.filter(
            (record) =>
              record.Type === "AAAA" &&
              record.Name.includes(hostname) &&
              record.Name != `${hostname}.`
          )
        )
        .then((currentRecordsReponse) =>
          currentRecordsReponse.map((record) => {
            const newResourceRecords = record.ResourceRecords?.map(
              (recordValue) => {
                const ipv6full = IPv6.fromHexadecimalString(recordValue.Value);
                const ipv6interface = IPv6.fromBigInteger(
                  ipv6mask.and(ipv6full.value)
                );
                const ipv6new = IPv6.fromBigInteger(
                  ipv6rangeFirst.add(ipv6interface.value)
                );
                return { Value: ipv6new.toString() };
              }
            );
            let newRecord = record;
            newRecord.ResourceRecords = newResourceRecords;
            return newRecord;
          })
        )
        .then((currentRecords) => {
          const changes = currentRecords
            .filter((r) => r.Type === "AAAA")
            .map((r) => {
              return {
                Action: "UPSERT",
                ResourceRecordSet: r,
              };
            });
          console.info(
            "CHANGED RECORD SET\n" + JSON.stringify(changes, null, 2)
          );
          return changes;
        });
      changeResults.push(
        changesPromise.then((changes) =>
          route53
            .changeResourceRecordSets({
              HostedZoneId: zoneId,
              ChangeBatch: {
                Changes: changes,
              },
            })
            .promise()
            .then((resp) => {
              console.info("CHANGE INFO\n" + JSON.stringify(resp, null, 2));
              return resp;
            })
            .catch((error) => {
              console.error("CHANGE ERROR\n" + JSON.stringify(error, null, 2));
              return error;
            })
        )
      );
    }

    return Promise.all(changeResults)
      .then((results) =>
        route53
          .listResourceRecordSets({
            HostedZoneId: zoneId,
          })
          .promise()
          .then((resp) =>
            resp.ResourceRecordSets.filter(
              (record) =>
                (record.Type === "A" || record.Type === "AAAA") &&
                record.Name.includes(hostname)
            )
          )
          .then((finalRecords) => {
            const responseData = {
              parameter: {
                hostname: hostname,
                ip: ip,
                ip6: ip6,
              },
              action: action,
              records: finalRecords,
            };

            console.info("RESPONSE\n" + JSON.stringify(responseData, null, 2));
            return {
              statusCode: 200,
              body: JSON.stringify(responseData),
            };
          })
      )
      .catch((error) => {
        console.error("ERROR\n" + JSON.stringify(error, null, 2));
        return {
          statusCode: 500,
          body: JSON.stringify(error),
        };
      });
  },
});

// Create an API endpoint
const endpoint = passhashsecret.apply(
  (passhash) =>
    new awsx.apigateway.API("update-dns-lambda", {
      routes: [
        {
          path: "/updatedns.php",
          method: "GET",
          eventHandler: handler,
          authorizers: [
            {
              authorizerName: "basicAuthorizer",
              parameterName: "auth",
              parameterLocation: "header",
              authType: "custom",
              type: "request",
              handler: async (event: awsx.apigateway.AuthorizerEvent) => {
                var authorizationHeader = event.headers?.Authorization;

                if (!authorizationHeader) throw new Error("Unauthorized");

                var encodedCreds = authorizationHeader.split(" ")[1];
                var plainCreds = Buffer.from(encodedCreds, "base64")
                  .toString()
                  .split(":");
                var username = plainCreds[0];
                var password = plainCreds[1];

                if (
                  !(
                    username === user &&
                    bcryptjs.compareSync(password, passhash)
                  )
                )
                  throw new Error("Unauthorized");

                return awsx.apigateway.authorizerResponse(
                  "user",
                  "Allow",
                  event.methodArn
                );
              },
              identitySource: ["method.request.header.Authorization"],
            },
          ],
        },
      ],
    })
);

const basicAuthResponse = new aws.apigateway.Response("basicAuthError", {
  responseParameters: {
    "gatewayresponse.header.WWW-Authenticate": "'Basic'",
  },
  responseTemplates: {
    "application/json": "{'message':$context.error.messageString}",
  },
  responseType: "UNAUTHORIZED",
  restApiId: endpoint.restAPI.id,
  statusCode: "401",
});

// Provision an SSL certificate to enable SSL -- ensuring to do so in us-east-1.
const awsUsEast1 = new aws.Provider("usEast1", { region: "us-east-1" });
const sslCert = new aws.acm.Certificate(
  "sslCert",
  {
    domainName: domain,
    validationMethod: "DNS",
  },
  { provider: awsUsEast1 }
);

// Create the necessary DNS records for ACM to validate ownership, and wait for it.
const sslCertValidationRecord = new aws.route53.Record(
  "sslCertValidationRecord",
  {
    zoneId: zoneId,
    name: sslCert.domainValidationOptions[0].resourceRecordName,
    type: sslCert.domainValidationOptions[0].resourceRecordType,
    records: [sslCert.domainValidationOptions[0].resourceRecordValue],
    ttl: 10 * 60 /* 10 minutes */,
  }
);
const sslCertValidationIssued = new aws.acm.CertificateValidation(
  "sslCertValidationIssued",
  {
    certificateArn: sslCert.arn,
    validationRecordFqdns: [sslCertValidationRecord.fqdn],
  },
  { provider: awsUsEast1 }
);

// Configure an edge-optimized domain for our API Gateway. This will configure a Cloudfront CDN
// distribution behind the scenes and serve our API Gateway at a custom domain name over SSL.
const webDomain = new aws.apigateway.DomainName("webCdn", {
  certificateArn: sslCertValidationIssued.certificateArn,
  domainName: domain,
});
const webDomainMapping = new aws.apigateway.BasePathMapping(
  "webDomainMapping",
  {
    restApi: endpoint.restAPI,
    stageName: endpoint.stage.stageName,
    domainName: webDomain.id,
  }
);

// Finally create an A record for our domain that directs to our custom domain.
const webDnsRecord = new aws.route53.Record(
  "webDnsRecord",
  {
    name: webDomain.domainName,
    type: "A",
    zoneId: zoneId,
    aliases: [
      {
        evaluateTargetHealth: true,
        name: webDomain.cloudfrontDomainName,
        zoneId: webDomain.cloudfrontZoneId,
      },
    ],
  },
  { dependsOn: sslCertValidationIssued }
);

exports.raw_endpoint = endpoint.url;
exports.endpoint = pulumi.interpolate`https://${webDomain.domainName}/`;
