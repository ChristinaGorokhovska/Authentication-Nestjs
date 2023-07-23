import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext) {
    const roles = this.reflector.get<string[]>('roles', context.getHandler());
    if (!roles) return true;

    const req = context.switchToHttp().getRequest();
    const user = req.user;
    const hasRole = () =>
      user.roles.some((role: string) => roles.indexOf(role) > -1);

    return hasRole();
  }
}
