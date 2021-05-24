import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as awsx from "@pulumi/awsx";
import * as bcryptjs from "bcryptjs";
import * as _ from "lodash";
import { isIPv4, isIPv6 } from "net";

const config = new pulumi.Config();

const zoneId = config.require("zoneid");
const domain = config.require("domain");
const ttl = parseInt(config.require("ttl"));
const user = config.require("user");
// get the hash in plaintext
const passhash = config.require("passhash");

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

const handler = new aws.lambda.CallbackFunction("update-dns-lambda-callback", {
  role: updateDnsRole,
  callback: async (event: awsx.apigateway.Request) => {
    console.info("QUERY STRING PARAMETERS\n" + JSON.stringify(event.queryStringParameters, null, 2));
    const hostname = event.queryStringParameters?.hostname;
    const ip = event.queryStringParameters?.ip;
    const ip6 = event.queryStringParameters?.ip6;

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
    const action = ip || ip6 ? "UPDATE" : "GET";

    const route53 = new aws.sdk.Route53();

    if (action === "UPDATE") {
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
      const changedRecordSet = await route53
        .changeResourceRecordSets({
          HostedZoneId: zoneId,
          ChangeBatch: {
            Changes: changes,
          },
        })
        .promise();
      console.info("CHANGED RECORD SET\n" + JSON.stringify(changedRecordSet, null, 2));
    }

    const currentRecords = await route53
      .listResourceRecordSets({
        HostedZoneId: zoneId,
        StartRecordName: hostname,
        StartRecordType: "A",
        MaxItems: "2",
      })
      .promise();

    const data = currentRecords.ResourceRecordSets.map((recordSet) => {
      return {
        name: recordSet.Name,
        type: recordSet.Type,
        ttl: recordSet.TTL,
        value: recordSet.ResourceRecords?.map((v) => v.Value),
      };
    }).filter((record) => record.name === `${hostname}.`);

    const response = {
      parameter: {
        hostname: hostname,
        ip: ip,
        ip6: ip6,
      },
      action: action,
      records: data,
    };

    console.info("RESPONSE\n" + JSON.stringify(response, null, 2));

    return {
      statusCode: 200,
      body: JSON.stringify(response),
    };
  },
});

// Create an API endpoint
const endpoint = new awsx.apigateway.API("update-dns-lambda", {
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
              !(username === user && bcryptjs.compareSync(password, passhash))
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
});

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
