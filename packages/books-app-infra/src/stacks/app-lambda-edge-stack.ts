import path from 'path';
import * as cdk from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';

export class AppLambdaEdgeStack extends cdk.Stack {
  customIamRole: cdk.aws_iam.Role;
  constructor(scope: Construct, id: string) {
    super(scope, id, {
      env: {
        region: 'us-east-1',
      },
    });

    // Create role for Lambda@Edge functions
    this.customIamRole = new cdk.aws_iam.Role(this, 'AllowLambdaServiceToAssumeRole', {
      assumedBy: new cdk.aws_iam.CompositePrincipal(
        new cdk.aws_iam.ServicePrincipal('lambda.amazonaws.com'),
        new cdk.aws_iam.ServicePrincipal('edgelambda.amazonaws.com'),
      ),
      managedPolicies: [cdk.aws_iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')],
    });
    this.customIamRole.addToPolicy(new cdk.aws_iam.PolicyStatement({
      actions: [
        'ssm:GetParameter',
        'ssm:GetParameters',
        'ssm:GetParametersByPath',
      ],
      resources: ['*'],
    }));

    const authLambda=new cdk.aws_cloudfront.experimental.EdgeFunction(this, 'AuthFunction', {
      runtime: Runtime.NODEJS_18_X,
      handler: 'index.handler',
      code: cdk.aws_lambda.Code.fromAsset(path.join(__dirname, '../edge-lambda/build/')),
      role: this.customIamRole,
    });
    authLambda.addAlias('live');

    new cdk.aws_ssm.StringParameter(this, 'AuthFunctionArnParam', {
      parameterName: 'EdgeFunctionArn',
      stringValue: authLambda.currentVersion.functionArn,
    });
  }
}
