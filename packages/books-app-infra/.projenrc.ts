import { awscdk } from 'projen';
import {NodePackageManager} from "projen/lib/javascript";
const project = new awscdk.AwsCdkTypeScriptApp({
  cdkVersion: '2.88.0',
  defaultReleaseBranch: 'main',
  name: 'books-app-infra',
  projenrcTs: true,
  deps: ['aws-cdk-lib', 'constructs', 'cognito-at-edge', '@aws-sdk/client-ssm'],
  packageManager: NodePackageManager.NPM,

  // deps: [],                /* Runtime dependencies of this module. */
  // description: undefined,  /* The description is just a string that helps people understand the purpose of the package. */
  // devDeps: [],             /* Build dependencies for this module. */
  // packageName: undefined,  /* The "name" in package.json. */
});

project.addTask('bundle-edge-lambda').exec('esbuild src/edge-lambda/index.ts --bundle --platform=node --target=node18 --external:@aws-sdk/client-ssm --outfile=src/edge-lambda/build/index.js');
project.addTask('zip-edge-lambda').exec('zip -r src/edge-lambda/build/index.zip src/edge-lambda/build/index.js*');


project.synth();
