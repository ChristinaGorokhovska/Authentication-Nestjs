import { Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class AccessTGuard extends AuthGuard('jwt') {
  constructor(reflector: Reflector) {
    super();
  }
}
