import { Injectable } from '@angular/core';
import { Book } from '../model/Book.model';
import { Observable } from 'rxjs';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})
export class DataServiceService {

  private apiUrl = 'https://n4dvcv50p1.execute-api.eu-central-1.amazonaws.com/dev/v1/books';

  constructor(private http: HttpClient) { }

  getBooksApi(): Observable<Book[]> {
    return this.http.get<Book[]>(this.apiUrl);
  }

  getBookApi(id: string): Observable<Book | any> {
    return this.http.get<Book>(`${this.apiUrl}/${id}`);
  }

  addBookApi(book: Book): Observable<Book> {
    return this.http.post<Book>(this.apiUrl, JSON.stringify(book));
  }

  updateBookApi(book: Book): Observable<Book> {
    return this.http.put<Book>(`${this.apiUrl}`, book);
  }

  deleteBookApi(id: string): Observable<any> {
    return this.http.delete(`${this.apiUrl}/${id}`);
  }

}
