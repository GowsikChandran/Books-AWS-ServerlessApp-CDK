import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {Api, matchUrl} from "./utils/url-helper";
import {generateErrorResponse, generateResponse, Response} from "./utils/response-helper";
import {Book} from "./interfaces/book.interface";
import {diContainer} from "./di/di-registry";
import {diConstants} from "./di/di-constants";
import {BooksController} from "./controllers/books-controller";


export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
    try {
        const {httpMethod, path, body} = event;

        if (httpMethod === 'OPTIONS') {
            // Preflight request. Reply successfully:
            return generateResponse(Response.Success.statusCode,
                JSON.stringify('CORS check passed safe to proceed.'));

        } else {

            const booksController: BooksController = diContainer.resolve(diConstants.BooksController);

            if (matchUrl(Api.books.basePath, path)) {
                if (httpMethod === 'GET') {
                    const books = await booksController.getAllBooks();
                    return generateResponse(Response.Success.statusCode, books);

                } else if (httpMethod === 'POST') {

                    const book = await booksController.createBook(JSON.parse(body || '{}') as Book);
                    return generateResponse(Response.Created.statusCode, book);

                } else if (httpMethod === 'PUT') {
                    const book = await booksController.updateBook(JSON.parse(body || '{}') as Book);
                    return generateResponse(Response.Success.statusCode, book);

                } else {
                    return generateErrorResponse(Response.MethodNotAllowed.statusCode, Response.MethodNotAllowed.message);
                }

            } else if (matchUrl(Api.books.basePathWithId, path)) {
                if (httpMethod === 'GET') {
                    // @ts-ignore
                    const {params} = matchUrl(Api.books.basePathWithId, path);
                    const book = await booksController.getBookById(params.id);
                    return generateResponse(Response.Success.statusCode, book);

                } else if (httpMethod === 'DELETE') {
                    // @ts-ignore
                    const {params} = matchUrl(Api.books.basePathWithId, path);
                    const responseCode = await booksController.deleteBookById(params.id);
                    if (responseCode === 204) {
                        return generateResponse(Response.NoContent.statusCode, Response.NoContent.message);
                    } else {
                        return generateResponse(Response.NotFound.statusCode, Response.NotFound.message);
                    }
                } else {
                    return generateErrorResponse(Response.MethodNotAllowed.statusCode, Response.MethodNotAllowed.message);
                }

            } else {
                return generateErrorResponse(Response.NotFound.statusCode, Response.NotFound.message);
            }
        }
    } catch (error) {
    return generateErrorResponse(Response.InternalServerError.statusCode, error);
}
}
