import { SSMClient, GetParametersCommand } from '@aws-sdk/client-ssm';
import { Authenticator } from 'cognito-at-edge';

const ssmClient = new SSMClient({ region: 'eu-central-1' });

// Function to get parameters
async function getParameters() {
  const command = new GetParametersCommand({
    Names: [
      'BooksAppCognitoUserPoolId',
      'BooksAppCognitoUserPoolClientId',
      'BooksAppCognitoUserPoolDomain',
    ],
    WithDecryption: false,
  });

  const response = await ssmClient.send(command);

  const userPoolId = response.Parameters?.find((param) => param.Name === 'BooksAppCognitoUserPoolId')?.Value;
  const userPoolClientId = response.Parameters?.find((param) => param.Name === 'BooksAppCognitoUserPoolClientId')?.Value;
  const userPoolDomain = response.Parameters?.find((param) => param.Name === 'BooksAppCognitoUserPoolDomain')?.Value;

  return { userPoolId, userPoolClientId, userPoolDomain };
}


let authenticatorPromise: Promise<Authenticator> = (async () => {
  const { userPoolId, userPoolClientId, userPoolDomain } = await getParameters();
  return new Authenticator({
    region: 'us-east-1', // user pool region
    userPoolId: userPoolId!, // user pool ID
    userPoolAppId: userPoolClientId!, // user pool app client ID
    userPoolDomain: `${userPoolDomain!}.auth.eu-central-1.amazoncognito.com`, // user pool domain
  });
})();

export const handler = async (request: any) => {
  const authenticator = await authenticatorPromise;
  return authenticator.handle(request);
};
