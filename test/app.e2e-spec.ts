import { Test } from '@nestjs/testing'
import { AppModule } from './../src/app.module'
import { INestApplication } from '@nestjs/common'
import { ValidationPipe } from '@nestjs/common/pipes'
import { PrismaService } from '../src/prisma/prisma.service'
import * as pactum from 'pactum'
import { AuthDto } from 'src/auth/dto'
import { EditUserDto } from 'src/user/dto'
import { CreateBookmarkDto, EditBookmarkDto } from 'src/bookmark/dto'

describe('App e2e', () => {
  let app : INestApplication
  let prisma : PrismaService  

  beforeAll(async() => {
    const moduleRef = await Test.createTestingModule({
      imports : [AppModule],
    }).compile()

    app = moduleRef.createNestApplication()
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist : true
      })
    )

    await app.init()
    await app.listen(3333)

    prisma = app.get(PrismaService)
    await prisma.cleanDb()
    pactum.request.setBaseUrl("http://localhost:3333")
  })
  
  afterAll(async () => {
    await app.close()
  })

  describe('Auth', () => {
    const dto: AuthDto = {
      email: 'tester@gmail.com',
      password: '123',
    };

    describe('Signup', () => {

      it('should throw if email empty', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody({ password : dto.password })
          .expectStatus(400)
      })

      it('should throw if password empty', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody({ email : dto.email })
          .expectStatus(400)
      })

      it('should throw if no body provider', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .expectStatus(400)
      })

      it('should signup', () => {
        return pactum
          .spec()
          .post('/auth/signup')
          .withBody(dto)
          .expectStatus(201);
      });
    });

    describe('Signin', () => {
      let accessToken : string
      it('should throw if email empty', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .withBody({ password : dto.password })
          .expectStatus(400)
      })

      it('should throw if password empty', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .withBody({ email : dto.email })
          .expectStatus(400)
      })

      it('should throw if no body provider', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .expectStatus(400)
      })

      it('should signin', () => {
        return pactum
          .spec()
          .post('/auth/signin')
          .withBody(dto)
          .expectStatus(200)
          .stores('userAccessToken', 'access_token')
      });

    });
  });

  describe('User', () => {
    describe('Get me', () => {
      it('should get current user', () => {
        return pactum
          .spec()
          .get('/users/me')
          .withHeaders({
            Authorization : 'Bearer $S{userAccessToken}'
          })
          .expectStatus(200)
      })
    })

    describe('Edit User', () => {
      it('should edit user', () => {
        const dto : EditUserDto = {
          firstName : "tester updated", 
          email : "tester@yahoo.com"
        }
        return pactum
          .spec()
          .patch('/users')
          .withHeaders({
            Authorization : 'Bearer $S{userAccessToken}'
          })
          .withBody(dto)
          .expectStatus(200)
          .expectBodyContains(dto.firstName)
          .expectBodyContains(dto.email)
      })
    })
  })
  
  describe('Bookmarks', () => {
    describe('Get empty bookmarks', () => {
      it('should get bookmarks', () => {
        return pactum
          .spec()
          .get('/bookmarks')
          .withHeaders({
            Authorization : 'Bearer $S{userAccessToken}'
          })
          .expectStatus(200)
          .expectBody([])
      })
    });
    
    describe('Create Bookmark', () => {
      it('should create bookmark', () => {
        const dto : CreateBookmarkDto = {
          title : "First Bookmark",
          link : "https://www.notion.so/Week-to-do-list-f29b73ed1c60420b8c49a1893900f15c"
        }

        return pactum 
          .spec()
          .post('/bookmarks')
          .withHeaders({
            Authorization : 'Bearer $S{userAccessToken}'
          })
          .withBody(dto)
          .expectStatus(201)
      })
    });

    describe('Get Bookmarks', () => {
      it('should get bookmarks', () => {
        return pactum
          .spec()
          .get('/bookmarks')
          .withHeaders({
            Authorization: 'Bearer $S{userAccessToken}',
          })
          .expectStatus(200)
          .expectJsonLength(1)
          .stores('bookmarkId', 'id')
      });
    });

    describe('Get Bookmark by id', () => {
      it('should get bookmarks by id', () => {
        return pactum
          .spec()
          .get('/bookmarks/{id}')
          .withPathParams('id', '$S{bookmarkId}')
          .withHeaders({
            Authorization: 'Bearer $S{userAccessToken}',
          })
          .expectStatus(200)
      });
    });

    describe('Edit Bookmark', () => {
      const dto : EditBookmarkDto = {
        title : "My todo list bookmark",
        description : "My description of todo list bookmark"
      }

      it('should update bookmark', () => {
        return pactum
          .spec()
          .patch('/bookmarks/{id}')
          .withPathParams('id', '$S{bookmarkId}')
          .withBody(dto)
          .withHeaders({
            Authorization : 'Bearer $S{userAccessToken}'
          })
          .expectStatus(200)
      })
    });

    describe('Delete Bookmark', () => {
      it('should delete bookmark', () => {
        return pactum
          .spec()
          .delete('/bookmarks/{id}')
          .withPathParams('id', '$S{bookmarkId}')
          .withHeaders({
            Authorization : 'Bearer $S{userAccessToken}'
          })
          .expectStatus(204)
      })
 
      it('should get bookmarks', () => {
        return pactum
          .spec()
          .get('/bookmarks')
          .withHeaders({
            Authorization : 'Bearer $S{userAccessToken}'
          })
          .expectStatus(200)
          .expectJsonLength(0)
          .inspect()
      })
    });
  });

})
