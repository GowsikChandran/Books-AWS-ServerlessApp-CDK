import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';

export const TABLE_NAME = 'BooksTable';
export const ddbClient = new DynamoDBClient({ region: 'eu-central-1' });
export const ddbDocClient = DynamoDBDocumentClient.from(new DynamoDBClient({ region: 'eu-central-1' }));
