import { App } from 'aws-cdk-lib';
import {AppCognitoStack} from "./stacks/app-cognito-stack";
import {AppSwaggerStack} from "./stacks/app-swagger-stack";
import {AppLambdaEdgeStack} from "./stacks/app-lambda-edge-stack";
import {AppStack} from "./stacks/app-stack";
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
  stage:'dev'
};

const app = new App();

const appLambdaEdgeStack = new AppLambdaEdgeStack(app, `books-cdk-lambda-edge-stack-${env.stage}`);

const appSwaggerStack = new AppSwaggerStack(app, `books-cdk-swagger-stack-${env.stage}`, {
  env: env,
});

const booksCognitoStack = new AppCognitoStack(app, `books-cdk-cognito-stack-${env.stage}`, {
  env: env,
  swaggerDistribution: appSwaggerStack.swaggerDistribution,
});



const booksAppStack= new AppStack(app, `books-cdk-app-stack-${env.stage}`, {
  env: env,
  userPool: booksCognitoStack.userPool,
});

new AppFrontendStack(app, `books-cdk-frontend-stack-${env.stage}`, {
  env: env,
});


appSwaggerStack.addDependency(appLambdaEdgeStack);
booksCognitoStack.addDependency(appSwaggerStack)
booksAppStack.addDependency(booksCognitoStack)

app.synth();
