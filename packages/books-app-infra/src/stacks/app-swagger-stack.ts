
import * as cdk from 'aws-cdk-lib';
import { aws_s3, RemovalPolicy } from 'aws-cdk-lib';
import {LambdaEdgeEventType, OriginAccessIdentity} from 'aws-cdk-lib/aws-cloudfront';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import { S3Origin } from 'aws-cdk-lib/aws-cloudfront-origins';
import { BlockPublicAccess, BucketAccessControl } from 'aws-cdk-lib/aws-s3';
import * as s3_deploy from 'aws-cdk-lib/aws-s3-deployment';
import { Construct } from 'constructs';
import { env } from '../main';
import {AwsCustomResource, AwsCustomResourcePolicy, PhysicalResourceId} from "aws-cdk-lib/custom-resources";
export interface AppSwaggerStackProps extends cdk.StackProps {
  env: env;
}

export class AppSwaggerStack extends cdk.Stack {
  swaggerBucket: aws_s3.IBucket;
  swaggerDistribution: cdk.aws_cloudfront.IDistribution;

  constructor(scope: Construct, id: string, props: AppSwaggerStackProps) {
    super(scope, id, props);
    this.swaggerBucket = new cdk.aws_s3.Bucket(this, `BooksAppSwaggerBucket-${props.env.stage}`, {
      bucketName: `books-app-swagger-bucket-${props.env.stage}`,
      blockPublicAccess: BlockPublicAccess.BLOCK_ACLS,
      accessControl: BucketAccessControl.BUCKET_OWNER_FULL_CONTROL,
      removalPolicy: RemovalPolicy.DESTROY,
    });


    const originAccessIdentity = new OriginAccessIdentity(
      this,
      'OriginAccessIdentityBooksAppSwagger',
    );
    this.swaggerBucket.grantReadWrite(originAccessIdentity);

      const resource = new AwsCustomResource(
          this,
          'AuthFunctionResource',
          {
              onUpdate: {
                  // will also be called for a CREATE event
                  service: 'SSM',
                  action: 'getParameter',
                  parameters: {
                      Name: 'EdgeFunctionArn',
                  },
                  region: 'us-east-1',
                  physicalResourceId: PhysicalResourceId.of(Date.now().toString()), // Update physical id to always fetch the latest version
              },
              policy: AwsCustomResourcePolicy.fromSdkCalls({
                  resources: AwsCustomResourcePolicy.ANY_RESOURCE,
              }),
          },
      );
      const arn = resource.getResponseField('Parameter.Value');

      const functionVersion = cdk.aws_lambda.Version.fromVersionArn(this, 'LambdaEdgeArn',
          arn);

    this.swaggerDistribution = new cloudfront.Distribution(
      this,
      'CloudfrontDistributionBooksAppSwagger',
      {
        defaultBehavior: {
          origin: new S3Origin(this.swaggerBucket, { originAccessIdentity: originAccessIdentity }),
            edgeLambdas: [
                {
                    functionVersion: functionVersion,
                    eventType: LambdaEdgeEventType.VIEWER_REQUEST,
                },
            ],
        },
        defaultRootObject: 'index.html',
      },
    );

    new s3_deploy.BucketDeployment(
      this,
      'SwaggerUIBooksAppDeployment',
      {
        sources: [s3_deploy.Source.asset('swagger')],
        destinationBucket: this.swaggerBucket,
        distribution: this.swaggerDistribution,
      },
    );
  }
}
