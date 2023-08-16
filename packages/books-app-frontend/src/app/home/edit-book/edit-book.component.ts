import { Component, OnInit } from '@angular/core';
import { FormGroup, FormBuilder, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { Book } from 'src/app/model/Book.model';
import { DataServiceService } from 'src/app/service/data-service.service';

@Component({
  selector: 'app-edit-book',
  templateUrl: './edit-book.component.html',
  styleUrls: ['./edit-book.component.css']
})
export class EditBookComponent implements OnInit {
  form!: FormGroup;
  id!: string;
  currentBook!: Book | undefined;

  constructor(
    private fb: FormBuilder,
    private bookService: DataServiceService,
    private activatedRoute: ActivatedRoute,
    private router: Router
  ) { }

  ngOnInit() {
    this.id = this.activatedRoute.snapshot.params["id"];
    this.bookService.getBookApi(this.id).subscribe(
      (book: Book) => {
        this.currentBook = book;
        this.populateForm();
      },
      (error: any) => {
        console.error("Error fetching book data: ", error);
      }
    );

    this.form = this.fb.group({
      id: [''],
      title: ['', Validators.required],
      author: ['', Validators.required],
      year: ['', Validators.required],
      genre: [''],
      isbn: [''],
      imageUrl: [''],
      description: [''],
    });
  }

  populateForm() {
    if (this.currentBook) {
      this.form.patchValue({
        id: this.currentBook.id,
        title: this.currentBook.title,
        author: this.currentBook.author,
        year: this.currentBook.year,
        genre: this.currentBook.genre,
        isbn: this.currentBook.isbn,
        imageUrl: this.currentBook.imageUrl,
        description: this.currentBook.description,
      });
    }
  }

  onSubmit() {
    if (this.form.valid) {
      this.bookService.updateBookApi(this.form.value).subscribe(
        () => {
          this.router.navigate(['/']);
        },
        (error: any) => {
          console.error("Error updating book data: ", error);
        }
      );
    }
  }
}
