[![Deploy](https://get.pulumi.com/new/button.svg)](https://app.pulumi.com/new)

# Serverless dyn dns with REST API

A simple dy dns server with REST API.

## Deploying and running the program

Note: some values in this example will be different from run to run.  These values are indicated
with `***`.

1.  Create a new stack:

    ```bash
    $ pulumi stack init dev
    ```

1.  Set configs region:

    ```
    $ pulumi config set aws:region eu-central-1
	$ pulumi config set ddns-lambda:domain ddns.example.com
    ```

1.  Restore NPM modules via `npm install` or `yarn install`.

1.  Run `pulumi up` to preview and deploy changes:

    ```
    $ pulumi up
    Previewing update of stack 'dev'
    ...

    Updating (dev):
    ...

    ```

1.  To view the runtime logs of the Lambda function, use the `pulumi logs` command. To get a log stream, use `pulumi logs --follow`.

## Clean up

1.  Run `pulumi destroy` to tear down all resources.

1.  To delete the stack itself, run `pulumi stack rm`. Note that this command deletes all deployment history from the Pulumi Console.
