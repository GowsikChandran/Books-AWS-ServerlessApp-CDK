import * as cdk from 'aws-cdk-lib';
import { RemovalPolicy } from 'aws-cdk-lib';
import { LambdaIntegration} from 'aws-cdk-lib/aws-apigateway';
import { AttributeType } from 'aws-cdk-lib/aws-dynamodb';
import { Construct } from 'constructs';
import { env } from '../main';
import path from "path";

export interface AppGatewayProps extends cdk.StackProps {
  env: env;
  userPool: cdk.aws_cognito.IUserPool;
}
export class AppStack extends cdk.Stack {
  apiGateway: cdk.aws_apigateway.IRestApi;
  function: cdk.aws_lambda.IFunction;
  dynamoDb: cdk.aws_dynamodb.ITable;
  constructor(scope: Construct, id: string, props: AppGatewayProps) {
    super(scope, id, props);

    this.apiGateway = new cdk.aws_apigateway.RestApi(this, `BooksAppApiGateway${props.env.stage}`, {
      restApiName: `BooksAppApiGateway${props.env.stage}`,
      deploy:false,
    });

    const deployment = new cdk.aws_apigateway.Deployment(this, 'BooksAppApiDeployment', {api: this.apiGateway});

    const stage = new cdk.aws_apigateway.Stage(this, `BooksAppApiStage${props.env.stage}`, {
      deployment,
      stageName: props.env.stage,
    });

    const apiUrl = `https://${this.apiGateway.restApiId}.execute-api.${this.region}.amazonaws.com/${stage.stageName}`;

    new cdk.CfnOutput(this, 'ApiUrl', {
      value: apiUrl,
    });


    this.function = new cdk.aws_lambda.Function(this, `BooksAppLambda${props.env.stage}`, {
      functionName: `BooksAppLambda${props.env.stage}`,
      code: cdk.aws_lambda.Code.fromAsset( path.join(__dirname, '../../../books-app-backend/dist/index.zip')),
      handler: 'index.handler',
      runtime: cdk.aws_lambda.Runtime.NODEJS_18_X,
    });


    const v1Resource = this.apiGateway.root.addResource('v1');
    v1Resource.addProxy({ defaultIntegration: new LambdaIntegration(this.function) });
    v1Resource.addResource('books');


    this.dynamoDb = new cdk.aws_dynamodb.Table(this, `BooksAppDynamoDb${props.env.stage}`, {
      tableName: 'BooksTable',
      partitionKey: { name: 'id', type: AttributeType.STRING },
      removalPolicy: RemovalPolicy.DESTROY,
    });
    this.dynamoDb.grantReadWriteData(this.function);
  }
}
