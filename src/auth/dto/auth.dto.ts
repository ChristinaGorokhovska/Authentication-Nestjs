import { IsNotEmpty } from 'class-validator';

export class AuthDto {
  @IsNotEmpty()
  readonly email: string;

  @IsNotEmpty()
  password: string;
}
