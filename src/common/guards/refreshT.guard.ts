import { AuthGuard } from '@nestjs/passport';

export class RefreshTGuard extends AuthGuard('jwt-refresh') {
  constructor() {
    super();
  }
}
