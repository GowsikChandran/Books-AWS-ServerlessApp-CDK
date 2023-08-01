import { Component, OnInit } from '@angular/core';
import { Book } from '../../model/Book.model';
import { DataServiceService } from '../../service/data-service.service';

@Component({
  selector: 'app-book-list',
  templateUrl: './book-list.component.html',
  styleUrls: ['./book-list.component.css']
})
export class BookListComponent implements OnInit {

  books: Book[] = [];
  filteredBooks: Book[] = [];
  filterSearch: string = '';

  constructor(private bookService: DataServiceService) { }

  ngOnInit(): void {
    this.getBooks();
  }

  getBooks() {
    this.bookService.getBooksApi().subscribe((books) => {
      this.books = books;
      this.filteredBooks = books;
    });
  }

  onSearch(query: string): void {
    this.filterSearch = query.trim().toLowerCase();
    this.filteredBooks = this.books.filter(
      (book) =>
        book.title.toLowerCase().includes(this.filterSearch) ||
        book.author.toLowerCase().includes(this.filterSearch)
    );
  }

  deleteBook(id: string): void {
    if (confirm('Are you sure you want to delete this book?')) {
      this.bookService.deleteBookApi(id).subscribe(() => {
        this.getBooks(); // Refresh the book list after deletion
      });
    }
  }
}
