
// Interface Definition
interface User {
  id: number;
  username: string;
  active: boolean;
  metadata?: Record<string, any>;
}

// Generic Stack Class
class Stack<T> {
  private items: T[] = [];

  push(item: T): void {
    this.items.push(item);
  }

  pop(): T | undefined {
    return this.items.pop();
  }

  peek(): T | undefined {
    return this.items[this.items.length - 1];
  }

  get length(): number {
    return this.items.length;
  }
}

// Service Class using Async/Await
class UserService {
  private users: Map<number, User> = new Map();

  constructor(initialUsers: User[]) {
    initialUsers.forEach(u => this.users.set(u.id, u));
  }

  async findUser(id: number): Promise<User | undefined> {
    // Simulate async delay
    // Note: setTimeout might behave differently depending on the runtime event loop
    return this.users.get(id);
  }

  getAllActive(): User[] {
    return Array.from(this.users.values()).filter(u => u.active);
  }
}

// Main Execution Block
const run = async () => {
  console.log("--- Starting Sovereign TS Simulation ---");

  const stack = new Stack<string>();
  stack.push("Nexus");
  stack.push("Core");
  console.log(`Stack Top: ${stack.peek()}`);

  const users: User[] = [
    { id: 1, username: "admin", active: true },
    { id: 2, username: "guest", active: false },
    { id: 3, username: "dev", active: true, metadata: { role: "engineer" } }
  ];

  const service = new UserService(users);
  console.log("Active Users:", service.getAllActive().map(u => u.username));

  const found = await service.findUser(3);
  if (found) {
    console.log(`Found User 3: ${found.username} (Role: ${found.metadata?.role})`);
  }

  console.log("--- Simulation Complete ---");
};

run().catch(err => console.error("Error:", err));
