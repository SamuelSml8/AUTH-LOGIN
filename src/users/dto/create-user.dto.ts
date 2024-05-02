import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MinLength,
  isString,
} from 'class-validator';

export class CreateUserDto {
  @IsString()
  readonly name: string;

  @IsNotEmpty()
  @IsEmail()
  readonly email: string;

  @IsNotEmpty()
  @MinLength(6, {message: "The password must be 6 characters"})
  readonly password: string;

  @IsString()
  readonly phone: string;
}
