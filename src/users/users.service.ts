import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

type Tokens = {
  access_token: string;
  refresh_token: string;
};

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtSvc: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto) {
    try {
      const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
      const newUser = new this.userModel({
        ...createUserDto,
        password: hashedPassword,
      });

      const user = await newUser.save();
      const { access_token, refresh_token } = await this.generateTokens(user);

      return {
        access_token,
        refresh_token,
        user: this.removePassword(user),
        status: HttpStatus.CREATED,
        message: 'User created succcesfully',
      };
    } catch (error) {
      throw new HttpException(
        'Please check your credentials',
        HttpStatus.UNAUTHORIZED,
      );
    }
  }

  async loginUser(email: string, password: string) {
    try {
      const user = await this.userModel.findOne({ email });
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        return new HttpException(
          'Please check your credentials',
          HttpStatus.UNAUTHORIZED,
        );
      }

      if (user && isPasswordValid) {
        const payload = { sub: user._id, email: user.email, name: user.name };
        const { access_token, refresh_token } =
          await this.generateTokens(payload);

        return {
          access_token,
          refresh_token,
          user: this.removePassword(user),
          message: 'Login succesfully',
        };
      }
    } catch (error) {
      throw new HttpException(
        'Please check your credentials',
        HttpStatus.UNAUTHORIZED,
      );
    }
  }

  async refreshToken(refreshToken) {
    try {
      const user = this.jwtSvc.verify(refreshToken, {
        secret: 'jwt secret_refresh',
      });

      const payload = { sub: user._id, email: user.email, name: user.name };
      const { access_token, refresh_token } =
        await this.generateTokens(payload);
      return {
        access_token,
        refresh_token,
        status: 200,
        message: 'Refresh token succesfully',
      };
    } catch (error) {
      throw new HttpException('Refresh token failed', HttpStatus.UNAUTHORIZED);
    }
  }

  private async generateTokens(user): Promise<Tokens> {
    const jwtPayload = { sub: user._id, email: user.email, name: user.name };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtSvc.signAsync(jwtPayload, {
        secret: 'jwt secret',
        expiresIn: '1d',
      }),
      this.jwtSvc.signAsync(jwtPayload, {
        secret: 'jwt secret_refresh',
        expiresIn: '7d',
      }),
    ]);
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  private removePassword(user) {
    const { password, ...rest } = user.toObject();
    return rest;
  }
}
