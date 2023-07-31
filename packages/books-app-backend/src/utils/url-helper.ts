import { match } from 'path-to-regexp';

export const Api = {
    books: {
        basePath: '/v1/books', // GET, POST, PUT
        basePathWithId: '/v1/books/:id', // GET, DELETE
    },
};
// helper function to match url
export function matchUrl(pattern: string, path: string) {
    return match(pattern, {
        decode: decodeURIComponent,
    })(path);
}
