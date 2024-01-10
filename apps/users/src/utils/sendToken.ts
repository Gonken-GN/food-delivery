import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';

export class TokenSender {
  constructor(
    private readonly config: ConfigService,
    private readonly jwt: JwtService,
  ) {}
  public sendToken(user: User) {
    const access_token = this.jwt.sign(
      {
        id: user.id,
      },
      {
        secret: this.config.get<string>('ACTIVATION_TOKEN_SECRET'),
      },
    );
    const refreshToken = this.jwt.sign(
      {
        id: user.id,
      },
      {
        secret: this.config.get<string>('REFRESH_TOKEN_SECRET'),
        expiresIn: '3d',
      },
    );
    return { user, access_token, refreshToken };
  }
}
