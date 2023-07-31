import * as cdk from "aws-cdk-lib";
import { RemovalPolicy} from "aws-cdk-lib";
import {Construct} from "constructs";
import {BlockPublicAccess, BucketAccessControl} from "aws-cdk-lib/aws-s3";
import {AwsCustomResource, AwsCustomResourcePolicy, PhysicalResourceId} from "aws-cdk-lib/custom-resources";
import {LambdaEdgeEventType, OriginAccessIdentity} from "aws-cdk-lib/aws-cloudfront";
import {S3Origin} from "aws-cdk-lib/aws-cloudfront-origins";
import * as s3_deploy from "aws-cdk-lib/aws-s3-deployment";
import { env } from '../main';
export interface AppFrontendStackProps extends cdk.StackProps {
    env: env;
}
export class AppFrontendStack extends cdk.Stack {
    frontendBucket: cdk.aws_s3.IBucket;
    frontendDistribution: cdk.aws_cloudfront.IDistribution;

    constructor(scope: Construct, id: string, props: AppFrontendStackProps) {
        super(scope, id, props);

        this.frontendBucket = new cdk.aws_s3.Bucket(this, `BooksAppFrontendBucket-${props.env.stage}`, {
            bucketName: `books-app-frontend-bucket-${props.env.stage}`,
            blockPublicAccess: BlockPublicAccess.BLOCK_ACLS,
            accessControl: BucketAccessControl.BUCKET_OWNER_FULL_CONTROL,
            removalPolicy: RemovalPolicy.DESTROY,
        });
        const originAccessIdentity = new OriginAccessIdentity(
            this,
            'OriginAccessIdentityBooksAppFrontend',
        );
        this.frontendBucket.grantReadWrite(originAccessIdentity);

        const resource = new AwsCustomResource(
            this,
            'AuthFunctionResource',
            {
                onUpdate: {
                    service: 'SSM',
                    action: 'getParameter',
                    parameters: {
                        Name: 'EdgeFunctionArn',
                    },
                    region: 'us-east-1',
                    physicalResourceId: PhysicalResourceId.of(Date.now().toString()),
                },
                policy: AwsCustomResourcePolicy.fromSdkCalls({
                    resources: AwsCustomResourcePolicy.ANY_RESOURCE,
                }),
            },
        );
        const arn = resource.getResponseField('Parameter.Value');

        const functionVersion = cdk.aws_lambda.Version.fromVersionArn(this, 'LambdaEdgeArn',
            arn);

        this.frontendDistribution = new cdk.aws_cloudfront.Distribution(
            this,
            'CloudfrontDistributionBooksAppFrontend',
            {
                defaultBehavior: {
                    origin: new S3Origin(this.frontendBucket, { originAccessIdentity: originAccessIdentity }),
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
            'FrontendBooksAppDeployment',
            {
                sources: [s3_deploy.Source.asset('../books-app-frontend/dist')],
                destinationBucket: this.frontendBucket,
                distribution: this.frontendDistribution,
            },
        );
    }

}
