import { App, Stage, StageProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { AppPipelineStack } from './stacks/app-pipeline-stack';
import { AppStack } from './stacks/app-stack';
import {AppCognitoStack} from "./stacks/app-cognito-stack";
import {AppLambdaEdgeStack} from "./stacks/app-lambda-edge-stack";
import {AppSwaggerStack} from "./stacks/app-swagger-stack";
import {AppFrontendStack} from "./stacks/app-frontend-stack";


export interface env {
  account: string | undefined;
  region: string | undefined;
  stage: string;
}
// for development, use account/region from cdk cli
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
  stage:'Dev',
};


const app = new App();


const cicd = new AppPipelineStack(app, 'AppPipelineStack', {
  env: env,
});

class BooksApp extends Stage {
  constructor(scope: Construct, id: string, props?: StageProps) {
    super(scope, id, props);

    const appLambdaEdgeStack = new AppLambdaEdgeStack(app, `BooksCdkLambdaEdgeStack${env.stage}`);

    const appSwaggerStack = new AppSwaggerStack(app, `BooksCdkSwaggerStack${env.stage}`, {
      env: env,
    });

    const appFrontendStack = new AppFrontendStack(app, `BooksCdkFrontendStack${env.stage}`, {
      env: env,
    });


    const booksCognitoStack = new AppCognitoStack(app, `BooksCdkCognitoStack${env.stage}`, {
      env: env,
      swaggerDistribution: appSwaggerStack.swaggerDistribution,
      frontEndDistribution: appFrontendStack.frontendDistribution,
    });

    const booksAppStack= new AppStack(this, `BooksCdkAppStack${env.stage}`, {
      env: env,
    });


    appSwaggerStack.addDependency(appLambdaEdgeStack);
    booksCognitoStack.addDependency(appSwaggerStack);
    booksCognitoStack.addDependency(appFrontendStack);
    booksAppStack.addDependency(booksCognitoStack);

  }
}

// Dev Account
cicd.pipeline.addStage(new BooksApp(app, 'Dev', {
  env: env,
}));
// Add multiple accounts and stages as required.

app.synth();
