const request = require("supertest");
const app = require("../app");

describe("Login Controller", () => {
  it("should return status code 200, token, and user object with email and subscription fields", async () => {
    const response = await request(app).post("/login").send({
      username: "modelexample@example.com", // (Trebuie sa fie valid!)
      password: "modelexample123456", // (Trebuie sa fie valid!)
    });

    // Verificăm status code-ul
    expect(response.status).toBe(200);

    // Verificăm dacă răspunsul conține un token
    expect(response.body).toHaveProperty("token");

    // Verificăm dacă răspunsul conține un obiect user cu câmpurile email și subscription
    expect(response.body.user).toBeDefined();
    expect(typeof response.body.user.email).toBe("string");
    expect(typeof response.body.user.subscription).toBe("string");
  });
});
