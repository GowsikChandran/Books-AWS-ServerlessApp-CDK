import {Body, Controller, Delete, Get, Post, Put, Response, Route, SuccessResponse, Tags} from "tsoa";
import {inject, injectable} from "tsyringe";
import {diConstants} from "../di/di-constants";
import {BooksService} from "../services/books-service";
import {Book} from "../interfaces/book.interface";

@injectable()
@Route('books')
@SuccessResponse('200', 'Success') // Custom success response
@Response<Error>('500', 'Internal Server Error') // Custom error response
export class BooksController extends Controller {
    constructor(@inject(diConstants.BooksService) private booksService: BooksService) {
        super();
    }

    @Get()
    @Tags('Books')
    async getAllBooks(): Promise<Book[]> {
        return this.booksService.getAllBooks();
    }

    @Get('{id}')
    @Tags('Books')
    async getBookById(id: string): Promise<Book> {
        return this.booksService.getBookById(id);
    }
    @Post()
    @Tags('Books')
    async createBook(@Body() book: Book): Promise<Book> {
        return this.booksService.createBook(book);
    }
    @Put()
    @Tags('Books')
    async updateBook(@Body() book: Book): Promise<Book> {
        return this.booksService.updateBook(book);
    }
    @Delete('{id}')
    @Tags('Books')
    async deleteBookById(id: string): Promise<number> {
        return this.booksService.deleteBookById(id);
    }
}
