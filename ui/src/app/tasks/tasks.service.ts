import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

import * as urls from '../constants/urls';
import { Task } from './task.model';

@Injectable({
  providedIn: 'root'
})
export class TasksService {
  private readonly TASK_URL: string;

  constructor(private httpClient: HttpClient) {
    this.TASK_URL = urls.APP_BASE_URL + urls.TASKS_BASE_URL;
  }

  getTasks() {
    return this.httpClient.get(this.TASK_URL);
  }

  addTasks(task: Task) {
    return this.httpClient.post(this.TASK_URL, task);
  }

  updateTasks(updatedTask: Task) {
    const url = this.TASK_URL + '/' + updatedTask.id;
    return this.httpClient.put(url, updatedTask);
  }

  deleteTasks(id: number) {
    const url = this.TASK_URL + '/' + id;
    return this.httpClient.delete(url);
  }
}
