import { IsEmail, IsNotEmpty, IsOptional, MinLength } from 'class-validator';

export class NewUserDto {
  @IsNotEmpty()
  readonly firstName: string;
  @IsNotEmpty()
  readonly lastName: string;
  readonly birthDate: Date;

  @IsOptional()
  readonly phone: string;

  @IsEmail()
  @IsNotEmpty()
  readonly email: string;

  @IsNotEmpty()
  @MinLength(8)
  password: string;
}
