import {injectable} from "tsyringe";
import {Book} from "../interfaces/book.interface";
import {DeleteCommand, GetCommand, PutCommand, ScanCommand, UpdateCommand} from "@aws-sdk/lib-dynamodb";
import {ddbDocClient, TABLE_NAME} from "../utils/db-helper";
import { v4 as uuidv4 } from 'uuid';

@injectable()
export class BooksRepository {

    async getAllBooks(): Promise<Book[]> {
        try {
            const params = {
                TableName: TABLE_NAME,
            };
            const command = new ScanCommand(params);
            const response = await ddbDocClient.send(command);
            console.log('Data fetched successfully');
            console.log(response);

            return response.Items as Book[];
        } catch (error) {
            console.error('Error getting data from DynamoDB:', error);
            throw error;
        }
    }
    async getBookById(id: string): Promise<Book> {
        try {
            const params = {
                TableName: TABLE_NAME,
                Key: {
                    id: id,
                },
            };
            const command = new GetCommand(params);
            const response = await ddbDocClient.send(command);
            console.log('Data fetched successfully');
            console.log(response);

            return response.Item as Book;
        } catch (error) {
            console.error('Error retrieving item from DynamoDB:', error);
            throw error;
        }
    }

    async createBook(book: Book): Promise<Book> {
        try {
            book.id =  uuidv4();
            const params = {
                TableName: TABLE_NAME,
                Item: book,
            };
            const command = new PutCommand(params);
            const response = await ddbDocClient.send(command);
            console.log('Data saved successfully');
            console.log(response);
            return await this.getBookById(book.id);
        } catch (error) {
            console.error('Error creating item in DynamoDB:', error);
            throw error;
        }
    }
    async updateBook(book: Book): Promise<Book> {
        try {
            const params = {
                TableName: TABLE_NAME,
                Key: {
                    id: book.id,
                },
                UpdateExpression: 'set title = :t, author = :a, #yr = :y, genre = :g, isbn = :i, imageUrl = :iu, description = :d',
                ExpressionAttributeValues: {
                    ':t': book.title,
                    ':a': book.author,
                    ':y': book.year,
                    ':g': book.genre,
                    ':i': book.isbn,
                    ':iu': book.imageUrl,
                    ':d': book.description,
                },
                ExpressionAttributeNames: {
                    "#yr": "year"
                },
                ReturnValues: 'ALL_NEW',
            };
            const command = new UpdateCommand(params);
            const response = await ddbDocClient.send(command);
            console.log('Data Updated successfully');
            console.log(response);

            return response.Attributes as Book;
        } catch (error) {
            console.error('Error Updating item in DynamoDB:', error);
            throw error;
        }
    }
    async deleteBookById(id: string): Promise<boolean> {
        try {
            const params = {
                TableName: TABLE_NAME,
                Key: {
                    id: id,
                },
                ReturnValues: "ALL_OLD"
            };
            const command = new DeleteCommand(params);
            const response = await ddbDocClient.send(command);
            console.log('Data deleted successfully');
            console.log(response);

            return response.Attributes !== undefined;
        } catch (error) {
            console.error('Error deleting item from DynamoDB:', error);
            throw error;
        }
    }
}
