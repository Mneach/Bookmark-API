import { ForbiddenException, Injectable } from "@nestjs/common"
import { PrismaService } from "src/prisma/prisma.service"
import { AuthDto } from "./dto"
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library"
import { JwtService } from "@nestjs/jwt/dist"
import { ConfigService } from "@nestjs/config/dist/config.service"

@Injectable()
export class AuthService{
    constructor(private prisma : PrismaService, private jwt : JwtService, private config: ConfigService){

    }

    async signup(dto : AuthDto){
        // generate the password hash
        const hash = await argon.hash(dto.password)

        // save the new user in the db
        try {
        const user = await this.prisma.user.create({
            data : {
                email : dto.email,
                hash
            },
            
        })
        
        delete user.hash
        // return the saved user
        return user;   
        } catch (error) {
           if(error instanceof PrismaClientKnownRequestError){
            if(error.code === 'P2002'){
                throw new ForbiddenException("Credential Taken")
            }
           } 

           throw error;
        }
        
    }

    async signin(dto : AuthDto){
        console.log(dto.email)
        //find the user by email
        const user = await this.prisma.user.findUnique({
            where : {
                email: dto.email
            }
        });

        //if user does not exits throw exception
        if(!user) throw new ForbiddenException('Email does not found!')

        // compare password
        const pwMatches = await argon.verify(user.hash, dto.password)

        // if password incorrect throw exception
        if(!pwMatches) throw new ForbiddenException('Credential incorrect')
        
        // send back jwt token
        return this.signToken(user.id, user.email)
    }

    async signToken(userId : number, email: string) : Promise<{access_token : string}>{
        const payload = {
            sub : userId,
            email
        }
        
        const secret = this.config.get("JWT_SECRET")
        
        const token = await this.jwt.signAsync(payload, {
            expiresIn : '15m',
            secret : secret            
        })

        return {
            access_token : token
        };
    }
}