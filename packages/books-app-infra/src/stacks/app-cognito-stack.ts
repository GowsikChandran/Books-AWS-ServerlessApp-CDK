
import * as cdk from 'aws-cdk-lib';
import { RemovalPolicy } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { env } from '../main';

export interface AppCognitoProps extends cdk.StackProps {
  env: env;
  swaggerDistribution: cdk.aws_cloudfront.IDistribution;
}
export class AppCognitoStack extends cdk.Stack {

  userPool: cdk.aws_cognito.IUserPool;
  constructor(scope: Construct, id: string, props: AppCognitoProps) {
    super(scope, id, props);

    this.userPool = new cdk.aws_cognito.UserPool(this, `BooksUserPool${props.env.stage}`, {
      standardAttributes: {
        email: {
          required: true,
          mutable: false,
        },
      },
      signInAliases: {
        email: true,
        username: true,
      },
      selfSignUpEnabled: true,
      autoVerify: { email: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // new cdk.aws_apigateway.CognitoUserPoolsAuthorizer(this, 'ApiGatewayCognitoAuthorizer', {
    //   cognitoUserPools: [this.userpool],
    // })._attachToApi(this.apigateway);

    const userPoolClient = this.userPool.addClient(`BooksAppUserPoolClient${props.env.stage}`, {
      authFlows: {
        adminUserPassword: true,
        userPassword: true,
      },
      generateSecret: false,
      oAuth: {
        flows: {
          authorizationCodeGrant: true,
          implicitCodeGrant: false,
          clientCredentials: false,
        },
        scopes: [cdk.aws_cognito.OAuthScope.OPENID],
        callbackUrls: [
          `https://${props.swaggerDistribution.distributionDomainName}`,
        ],
        logoutUrls: [
          `https://${props.swaggerDistribution.distributionDomainName}`,
        ],
      },
    });
    const userPoolDomain = this.userPool.addDomain(`BooksAppUserPoolDomain${props.env.stage}`, {
      cognitoDomain: {
        domainPrefix: 'books-app-cloudfront',
      },
    });

    new cdk.aws_ssm.StringParameter(this, 'BooksAppCognitoUserPoolId', {
      parameterName: 'BooksAppCognitoUserPoolId',
      stringValue: this.userPool.userPoolId,
    });
    new cdk.aws_ssm.StringParameter(this, 'BooksAppCognitoUserPoolClientId', {
      parameterName: 'BooksAppCognitoUserPoolClientId',
      stringValue: userPoolClient.userPoolClientId,
    });
    new cdk.aws_ssm.StringParameter(this, 'BooksAppCognitoUserPoolDomain', {
      parameterName: 'BooksAppCognitoUserPoolDomain',
      stringValue: userPoolDomain.domainName,
    });

    new cdk.aws_cognito.CfnUserPoolUser(this, 'MyCfnUserPoolDefaultUser', {
      userPoolId: this.userPool.userPoolId,
      username: 'chandran',
      forceAliasCreation: true,
      userAttributes: [{
        name: 'email',
        value: 'gowsik.kc@gmail.com',
      }, {
        name: 'email_verified',
        value: 'true',
      },
      ],
      clientMetadata: {
        'UserPoolClient': userPoolClient.userPoolClientId,
      },
    });
  }
}
