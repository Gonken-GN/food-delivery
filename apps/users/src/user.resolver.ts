import { BadRequestException, UseGuards } from '@nestjs/common';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { UsersService } from './users.service';
import {
  ActivationResponse,
  LogOutResponse,
  LoginResponse,
  RegisterResponse,
} from './types/user.types';
import { ActivationDTO, RegisterDTO } from './dto/user.dto';
import { User } from './entities/user.entity';
import { Response } from 'express';
import { AuthGuard } from './guards/auth.guard';

@Resolver('User')
export class UsersResolver {
  constructor(private readonly userService: UsersService) {}

  @Mutation(() => RegisterResponse)
  async register(
    @Args('registerDto') registerDTO: RegisterDTO,
    @Context() context: { res: Response },
  ): Promise<RegisterResponse> {
    if (!registerDTO.name || !registerDTO.email || !registerDTO.password) {
      throw new BadRequestException('Please fill all fields');
    }

    const { activation_token } = await this.userService.register(
      registerDTO,
      context.res,
    );
    return { activationToken: activation_token };
  }

  @Mutation(() => ActivationResponse)
  async activateUser(
    @Args('activationDto') activationDTO: ActivationDTO,
    @Context() context: { res: Response },
  ): Promise<ActivationResponse> {
    return await this.userService.activateUser(activationDTO, context.res);
  }

  @Mutation(() => LoginResponse)
  async login(
    @Args('email') email: string,
    @Args('password') password: string,
  ): Promise<LoginResponse> {
    return this.userService.login({ email, password });
  }

  @Query(() => LoginResponse)
  @UseGuards(AuthGuard)
  async getLoggedInUser(@Context() context: { req: Request }) {
    return await this.userService.getLoggedInUser(context.req);
  }

  @Query(() => LogOutResponse)
  @UseGuards(AuthGuard)
  async logOutUser(@Context() context: { req: Request }) {
    return await this.userService.logOut(context.req);
  }
  @Query(() => [User])
  async getAllUsers() {
    return this.userService.getAllUsers();
  }
}
