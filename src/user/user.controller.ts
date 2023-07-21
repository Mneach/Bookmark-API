import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import { JwtGuard } from 'src/auth/guard';
import { Request } from 'express'
import { GetUser } from 'src/auth/decorator';
import { User } from '@prisma/client';

@UseGuards(JwtGuard) 
@Controller('users')
export class UserController {

    @Get('me')
    getme(@GetUser() user : User){
        return user 
    }

}
