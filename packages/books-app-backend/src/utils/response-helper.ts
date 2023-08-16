import {APIGatewayProxyResult} from "aws-lambda";

export const headers = {
    'Content-Type': 'application/json',
    "Access-Control-Allow-Headers": '*',
    "Access-Control-Allow-Origin": '*',
    "Access-Control-Allow-Methods": '*',
    'Access-Control-Allow-Credentials': true,
};

export const generateResponse = (statusCode: number, body: any): APIGatewayProxyResult => ({
    statusCode: statusCode,
    headers: headers,
    body: JSON.stringify(body),
});
export const generateErrorResponse = (statusCode: number, errorMessage: any): APIGatewayProxyResult => ({
    statusCode: statusCode,
    headers: headers,
    body: JSON.stringify({ error: errorMessage }),
});

export const Response = {
    Success:{
        statusCode: 200,
        message: 'OK',
    },
    Created:{
        statusCode: 201,
        message: 'Created',
    },
    NoContent:{
        statusCode: 204,
        message: 'No Content',
    },
    BadRequest: {
        statusCode: 400,
        message: 'Bad Request',
    },
    Unauthorized: {
        statusCode: 401,
        message: 'Unauthorized',
    },
    NotFound: {
        statusCode: 404,
        message: 'Resource Not Found',
    },
    MethodNotAllowed: {
        statusCode: 404,
        message: 'Method Not Allowed',
    },
    InternalServerError: {
        statusCode: 500,
        message: 'Internal Server Error',
    },
};
