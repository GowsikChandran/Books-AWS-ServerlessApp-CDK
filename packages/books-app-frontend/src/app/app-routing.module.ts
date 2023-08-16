import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { AddBookComponent } from './home/add-book/add-book.component';
import { BookListComponent } from './home/book-list/book-list.component';
import { EditBookComponent } from './home/edit-book/edit-book.component';

const routes: Routes = [
  
  { path: 'home', component: BookListComponent },
  { path: 'home/book/:id', component: EditBookComponent },
  { path: 'add', component: AddBookComponent },
  { path: '', pathMatch:'full', redirectTo:'/home'},
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
