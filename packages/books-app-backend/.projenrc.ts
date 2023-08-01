import { typescript } from 'projen';
import {NodePackageManager} from "projen/lib/javascript";
const project = new typescript.TypeScriptAppProject({
  defaultReleaseBranch: 'main',
  name: 'books-app-backend',
  projenrcTs: true,
  deps: ['aws-lambda',
    '@aws-sdk/client-dynamodb',
    '@aws-sdk/lib-dynamodb',
      'uuid',
      'tsyringe',
      '@tsoa/runtime',
      'reflect-metadata',
      'path-to-regexp',
  ],
  devDeps: [
    '@types/aws-lambda',
    '@types/uuid',
    '@tsoa/cli',
     'tsoa',
  ],
  packageManager: NodePackageManager.NPM,

  // deps: [],                /* Runtime dependencies of this module. */
  // description: undefined,  /* The description is just a string that helps people understand the purpose of the package. */
  // devDeps: [],             /* Build dependencies for this module. */
  // packageName: undefined,  /* The "name" in package.json. */
});
project.addTask('bundle-backend-lambda')
    .exec('esbuild src/index.ts --bundle --platform=node --target=node18 --external:@aws-sdk/client-dynamodb --external:@aws-sdk/lib-dynamodb --minify --outfile=dist/index.js');
project.addTask('zip-backend-lambda')
    .exec('zip -j dist/index.zip dist/index.js');
project.addTask('update-backend-lambda')
    .exec('aws lambda update-function-code  --function-name BooksAppLambdadev  --region eu-central-1 --zip-file fileb://dist/index.zip');
project.addTask('esbuild-bundle-analyse')
    .exec('esbuild src/index.ts --bundle --platform=node --target=node18 --external:@aws-sdk/client-dynamodb --external:@aws-sdk/lib-dynamodb --outfile=dist/index.js --metafile=dist/meta.json');
// https://esbuild.github.io/analyze/

project.addTask('swagger-gen')
    .exec('npx tsoa spec-and-routes');
project.addTask('s3-upload')
    .exec('aws s3 cp build/swagger-config.json s3://books-app-swagger-bucket-dev/');
project.addTask('cloudfront-invalidate')
    .exec('aws cloudfront create-invalidation --distribution-id EODQM6B16MM9Q --paths /swagger-config.json');

project.synth();
