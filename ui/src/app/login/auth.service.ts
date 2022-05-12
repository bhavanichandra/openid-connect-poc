import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

import * as urls from '../constants/urls';
import { BehaviorSubject } from 'rxjs';

interface UserSubject {
  token: string;
  userId: number;
  isAuthenticated: boolean;
}

interface Login {
  username: string;
  password: string;
  email: string;
}

interface Register extends Login {
  firstName: string;
  lastName: string;
}

interface HttpResponse {
  success: boolean;
  data: any;
  message: string | null;
}

const INITIAL_USER_SUBJECT = {
  token: '',
  userId: 0,
  isAuthenticated: false
};

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  userSubject: BehaviorSubject<UserSubject> = new BehaviorSubject<UserSubject>(
    INITIAL_USER_SUBJECT
  );

  errorSubject: BehaviorSubject<any> = new BehaviorSubject<any>(null);
  private readonly AUTH_URL: string;

  constructor(private httpClient: HttpClient) {
    this.AUTH_URL = urls.APP_BASE_URL;
  }

  login(loginData: Login) {
    const url = this.AUTH_URL + urls.LOGIN_URL;
    this.httpClient
      .post<HttpResponse>(url, loginData)
      .subscribe((loginResponse) => {
        if (!loginResponse.success) {
          this.errorSubject.next(loginResponse.message);
          return;
        }
        this.userSubject.next({
          token: loginResponse.data.token,
          userId: loginResponse.data.user.id,
          isAuthenticated: !!loginResponse.data.key
        });
        localStorage.setItem('token', loginResponse.data.token);
        localStorage.setItem('user', JSON.stringify(loginResponse.data.user));
      });
  }

  register(registrationData: Register) {
    const url = this.AUTH_URL + urls.REGISTER_URL;
    return this.httpClient.post(url, registrationData);
  }

  autoLogin() {
    const token = localStorage.getItem('token');
    const userJson = localStorage.getItem('user');
    const user = userJson && JSON.parse(userJson);
    if (token && user) {
      this.userSubject.next({
        token: token,
        userId: user.id,
        isAuthenticated: !!token
      });
    }
  }

  logout() {
    this.userSubject.next(INITIAL_USER_SUBJECT);
    localStorage.clear();
  }
}
