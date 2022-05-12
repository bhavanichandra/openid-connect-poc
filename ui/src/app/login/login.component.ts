import { Component, OnDestroy, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { AuthService } from './auth.service';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css'],
})
export class LoginComponent implements OnInit, OnDestroy {
  loginForm: FormGroup = this.formBuilder.group({});
  showLoader: boolean = false;
  authSubscription: Subscription = new Subscription();
  isAuthenticated: boolean = false;

  constructor(
    private formBuilder: FormBuilder,
    private authService: AuthService
  ) {}

  ngOnInit(): void {
    this.loginForm = this.formBuilder.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(4)]],
    });
  }

  onLogin(event: any) {
    event.preventDefault();
    this.showLoader = true;
    const loginData = this.loginForm.value;
    this.authService.login({ ...loginData, username: loginData.email });
    this.authSubscription = this.authService.userSubject.subscribe((each) => {
      this.showLoader = false;
      this.isAuthenticated = each.isAuthenticated;
    });
  }
  ngOnDestroy() {
    if (this.authSubscription) {
      this.authSubscription.unsubscribe();
    }
  }
}
