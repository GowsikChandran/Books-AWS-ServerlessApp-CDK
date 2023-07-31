import { Component } from '@angular/core';
import { FormGroup, FormBuilder } from '@angular/forms';
import { Router } from '@angular/router';
import { DataServiceService } from 'src/app/service/data-service.service';

@Component({
  selector: 'app-add-book',
  templateUrl: './add-book.component.html',
  styleUrls: ['./add-book.component.css']
})
export class AddBookComponent {

  form!: FormGroup;
  
  constructor(private fb: FormBuilder, private bookService: DataServiceService, private router:Router) { }

  ngOnInit() {
    this.form = this.fb.group({
      
      title: [''],
      author: [''],
      year: [''],
      genre: [''],
      isbn: [''],
      imageUrl: [''],
      description: [''],
    })
  }

  onSubmit() {
    console.log(this.form.value);
    this.bookService.addBookApi(this.form.value).subscribe(() =>
      this.router.navigate(['/'])
      );
    
    
  }
}
