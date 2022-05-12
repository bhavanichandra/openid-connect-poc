export interface User {
  id: number;
  name: string;
  email: string;
  isSSOUser: boolean;
  SSOId: boolean;
}

export interface Task {
  id: number;
  name: string;
  description: string;
  user: number;
}
