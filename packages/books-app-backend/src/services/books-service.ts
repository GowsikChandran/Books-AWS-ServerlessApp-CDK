import {inject, injectable} from "tsyringe";
import {Book} from "../interfaces/book.interface";
import {BooksRepository} from "../repositories/book-repository";

@injectable()
export class BooksService {
    constructor(@inject(BooksRepository) private booksRepository: BooksRepository) {}

    public getAllBooks(): Promise<Book[]> {
        return this.booksRepository.getAllBooks();
    }
    async getBookById(id: string): Promise<Book> {
        return this.booksRepository.getBookById(id);
    }
    async createBook(book: Book): Promise<Book> {
        return this.booksRepository.createBook(book);
    }
    async updateBook(book: Book): Promise<Book> {
        return this.booksRepository.updateBook(book);
    }
    async deleteBookById(id: string): Promise<number> {
        const result =  await this.booksRepository.deleteBookById(id);
        return result ? 204 : 404;
    }
}
