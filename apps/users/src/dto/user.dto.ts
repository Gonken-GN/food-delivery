import { InputType, Field } from '@nestjs/graphql';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  isEmail,
  isNotEmpty,
  isString,
  minLength,
} from 'class-validator';

@InputType()
export class RegisterDTO {
  @Field()
  @isNotEmpty({ message: 'Name is required' })
  @isString({ message: 'Name must be a string' })
  name: string;

  @Field()
  @isNotEmpty({ message: 'Password is required' })
  @minLength(8, { message: 'Password must be at least 8 characters' })
  password: string;

  @Field()
  @isNotEmpty({ message: 'Email is required' })
  @isEmail({}, { message: 'Invalid email' })
  email: string;
}

@InputType()
export class LoginDTO {
  @Field()
  @isNotEmpty({ message: 'Email is required' })
  @isEmail({}, { message: 'Email must be valid' })
  email: string;

  @Field()
  @isNotEmpty({ message: 'Password is required' })
  password: string;
}
