import { PrismaService } from './../../../prisma/Prisma.service';

import {
  ActivationDTO,
  ForgotPasswordDTO,
  LoginDTO,
  RegisterDTO,
  ResetPassworDTO,
} from './dto/user.dto';
import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService, JwtVerifyOptions } from '@nestjs/jwt';
import { Response } from 'express';
import * as bcrypt from 'bcrypt';
import { EmailService } from './email/email.service';
import { TokenSender } from './utils/sendToken';
import { User } from '@prisma/client';

interface UserData {
  name: string;
  email: string;
  password: string;
  phone_number: number;
}

@Injectable()
export class UsersService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService,
    private readonly configService: ConfigService,
    private readonly emailService: EmailService,
  ) {}

  // Register user
  async register(registerDTO: RegisterDTO, response: Response) {
    const { name, email, password, phone_number } = registerDTO;
    const isEmailExist = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });

    const isPhoneNumberExist = await this.prismaService.user.findUnique({
      where: {
        phone_number,
      },
    });
    if (isPhoneNumberExist) {
      throw new BadRequestException(
        'User with this phone number Already Exist',
      );
    }
    if (isEmailExist) {
      throw new BadRequestException('User with this email Already Exist');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      name,
      email,
      password: hashedPassword,
      phone_number,
    };
    const activationToken = await this.createActivationToken(user);
    const activation_token = activationToken.token;
    const activationCode = activationToken.activationCode;
    await this.emailService.sendMail({
      email,
      subject: 'Activation Code',
      template: './activation-mail',
      name,
      activationCode,
    });
    return { activation_token, response };
  }
  // Create activation token
  async createActivationToken(user: UserData) {
    const activationCode = Math.floor(1000 + Math.random() * 9000).toString();

    const token = this.jwtService.sign(
      { user, activationCode },
      {
        secret: this.configService.get('ACTIVATION_SECRET'),
        expiresIn: '10m',
      },
    );
    return { token, activationCode };
  }

  // Activation User
  async activateUser(activationDTO: ActivationDTO, response: Response) {
    const { activationToken, activationCode } = activationDTO;

    const newUser: { user: UserData; activationCode: string } =
      this.jwtService.verify(activationToken, {
        secret: this.configService.get('ACTIVATION_SECRET'),
      } as JwtVerifyOptions);

    if (newUser.activationCode !== activationCode) {
      throw new BadRequestException('Invalid activation code');
    }

    const { name, email, password, phone_number } = newUser.user;
    const existUser = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });

    if (existUser) {
      throw new BadRequestException('User with this email Already Exist');
    }
    const user = await this.prismaService.user.create({
      data: {
        name,
        email,
        password,
        phone_number,
      },
    });
    return { user, response };
  }
  // Login user
  async login(loginDTO: LoginDTO) {
    const { email, password } = loginDTO;
    const user = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });
    if (user && (await this.comparePassword(password, user.password))) {
      const tokenSender = new TokenSender(this.configService, this.jwtService);
      return tokenSender.sendToken(user);
    } else {
      return {
        user: null,
        accessToken: null,
        refreshToken: null,
        error: {
          message: 'Invalid credentials',
        },
      };
    }
  }

  // Generate password link
  async generatePasswordLink(user: User) {
    const forgotPasswordToken = this.jwtService.sign(
      {
        user,
      },
      {
        secret: this.configService.get('FORGOT_PASSWORD_SECRET'),
      },
    );
    return forgotPasswordToken;
  }
  // Forgot Password
  async forgotPassword(forgotPasswordDto: ForgotPasswordDTO) {
    const { email } = forgotPasswordDto;
    const user = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      throw new BadRequestException('User with this email does not exist');
    }
    const forgotPasswordToken = await this.generatePasswordLink(user);

    const resetPasswordUrl =
      this.configService.get<string>('CLIENT_SIDE_URL') +
      `/reset-password/verify=${forgotPasswordToken}`;
    await this.emailService.sendMail({
      email,
      subject: 'Reset Password',
      template: './forgot-password',
      name: user.name,
      activationCode: resetPasswordUrl,
    });
    console.log(forgotPasswordToken);
    return { message: `Your forgot password request successfuly` };
  }
  // Reset Password
  async resetPassword(resetPasswordDto: ResetPassworDTO) {
    const { password, activationToken } = resetPasswordDto;
    const decode = await this.jwtService.decode(activationToken);

    if (!decode) {
      throw new BadRequestException('Invalid token');
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.prismaService.user.update({
      where: { id: decode.user.id },
      data: { password: hashedPassword },
    });
    return { user };
  }
  // Get Logged in user
  async getLoggedInUser(req: any) {
    const user = req.user;
    const accessToken = req.accesstoken;
    const refreshToken = req.refreshtoken;
    return { user, accessToken, refreshToken };
  }

  // Get Logged out user
  async logOut(req: any) {
    req.user = null;
    req.refreshtoken = null;
    req.accesstoken = null;
    return { message: 'Logged out successfully' };
  }
  // Compare password with hashed password
  async comparePassword(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return await bcrypt.compare(password, hashedPassword);
  }
  // Get All users
  async getAllUsers() {
    return this.prismaService.user.findMany({});
  }
}
