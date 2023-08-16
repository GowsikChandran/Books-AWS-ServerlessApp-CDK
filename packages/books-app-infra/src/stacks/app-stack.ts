import path from 'path';
import * as cdk from 'aws-cdk-lib';
import { aws_dynamodb as dynamodb, RemovalPolicy } from 'aws-cdk-lib';
import { LambdaIntegration } from 'aws-cdk-lib/aws-apigateway';
import { AttributeType } from 'aws-cdk-lib/aws-dynamodb';
import { Construct } from 'constructs';
import { env } from '../main';

export interface AppGatewayProps extends cdk.StackProps {
  env: env;
}
export class AppStack extends cdk.Stack {

  constructor(scope: Construct, id: string, props: AppGatewayProps) {
    super(scope, id, props);

    const apiGateway = new cdk.aws_apigateway.RestApi(this, `BooksAppApiGateway${props.env.stage}`, {
      restApiName: `BooksAppApiGateway${props.env.stage}`,
      deploy: false,
    });

    const deployment = new cdk.aws_apigateway.Deployment(this, 'BooksAppApiDeployment', { api: apiGateway });

    const stage = new cdk.aws_apigateway.Stage(this, `BooksAppApiStage${props.env.stage}`, {
      deployment,
      stageName: props.env.stage,
    });

    const apiUrl = `https://${apiGateway.restApiId}.execute-api.${this.region}.amazonaws.com/${stage.stageName}`;

    new cdk.CfnOutput(this, 'ApiUrl', {
      value: apiUrl,
    });


    const lambdaFunction= new cdk.aws_lambda.Function(this, `BooksAppLambda${props.env.stage}`, {
      functionName: `BooksAppLambda${props.env.stage}`,
      code: cdk.aws_lambda.Code.fromAsset( path.join(__dirname, '../../../books-app-backend/dist/index.zip')),
      handler: 'index.handler',
      runtime: cdk.aws_lambda.Runtime.NODEJS_18_X,
    });


    const v1Resource = apiGateway.root.addResource('v1');
    // Lambda proxy Integration
    v1Resource.addProxy({ defaultIntegration: new LambdaIntegration(lambdaFunction) });
    v1Resource.addResource('books');


    const table = new cdk.aws_dynamodb.Table(this, `BooksAppDynamoDb${props.env.stage}`, {
      tableName: 'BooksTable',
      partitionKey: { name: 'id', type: AttributeType.STRING }, // Partition key
      sortKey: { name: 'Title', type: AttributeType.STRING }, // Sort key
      billingMode: cdk.aws_dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    table.grantReadWriteData(lambdaFunction);

    // Add an LSI with the same partition key but different sort key
    table.addLocalSecondaryIndex({
      indexName: 'YearPublishedIndex',
      sortKey: { name: 'YearPublished', type: dynamodb.AttributeType.NUMBER },
    });

    // Add GSI 1: Query by Author and sort by Title
    table.addGlobalSecondaryIndex({
      indexName: 'AuthorTitleIndex',
      partitionKey: { name: 'Author', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'Title', type: dynamodb.AttributeType.STRING },
    });

    // Add GSI 2: Query by Genre and sort by Title
    table.addGlobalSecondaryIndex({
      indexName: 'GenreTitleIndex',
      partitionKey: { name: 'Genre', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'Title', type: dynamodb.AttributeType.STRING },
    });
  }
}
