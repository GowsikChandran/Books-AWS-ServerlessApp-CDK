import { Stack } from 'aws-cdk-lib';
import * as cdk from 'aws-cdk-lib';
import * as pipelines from 'aws-cdk-lib/pipelines';
import { CodePipeline } from 'aws-cdk-lib/pipelines';
import { Construct } from 'constructs';
import { env } from '../main';

interface AppPipelineStackProps extends cdk.StackProps {
  env: env;
}
export class AppPipelineStack extends Stack {
  readonly pipeline: CodePipeline;
  constructor(scope: Construct, id: string, props: AppPipelineStackProps) {
    super(scope, id, props);

    const owner = 'GowsikChandran';
    const repo = 'Books-AWS-ServerlessApp-CDK';
    const source = pipelines.CodePipelineSource.gitHub(owner +'/'+ repo, 'aws-single-pipeline-test', {
      authentication: cdk.SecretValue.secretsManager('github-token'),
    });

    this.pipeline = new pipelines.CodePipeline(this, 'BooksCDKPipeline', {
      pipelineName: 'BooksAppSinglePipeline',
      synth: new pipelines.ShellStep('Synth', {
        input: source,
        installCommands: [
          // 'npm install projen',
          'npm ci',
        ],
        commands: [
          // Build the Angular app
          'cd packages/books-app-frontend',
          'npx ng build --configuration production',
          'cd ../../', // Navigate back to the root directory

          // Build the backend Lambda app
          'cd packages/books-app-backend',
          'npx projen',
          'npx projen bundle-backend-lambda',
          'npx projen zip-backend-lambda',
          'npx projen swagger-gen',
          'cd ../../', // Navigate back to the root directory

          // Projen and CDK commands for the infrastructure
          'cd packages/books-app-infra',
          'npx projen',
          'npx projen build',
          'npx cdk synth',

        ],
        primaryOutputDirectory: 'packages/books-app-infra/cdk.out',
      }),
    });
  }
}
