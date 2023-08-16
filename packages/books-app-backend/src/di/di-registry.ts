import 'reflect-metadata';
import { container } from 'tsyringe';
import { diConstants } from './di-constants';
import {BooksRepository} from "../repositories/book-repository";
import {BooksService} from "../services/books-service";
import {BooksController} from "../controllers/books-controller";



container.register(diConstants.BooksRepository, BooksRepository);
container.register(diConstants.BooksService, BooksService);
container.register(diConstants.BooksController, BooksController);


export const diContainer = container;
