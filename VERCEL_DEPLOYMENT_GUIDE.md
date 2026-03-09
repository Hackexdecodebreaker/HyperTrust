# Deploying HyperTrust to Vercel

I have configured the codebase to be fully compatible with Vercel's serverless environment! Here is how you can deploy your application right now.

## What was changed?
1. **`vercel.json` Added**: We created the required configuration file that tells Vercel to use the `@vercel/python` builder and route all traffic to `app.py`.
2. **Ephemeral Storage (`config.py`)**: Vercel's backend filesystem is read-only, except for the `/tmp` directory. I added an environment variable check so that when Vercel runs your app, the SQLite database is safely stored in `/tmp/hypertrust.db`.
3. **App Bootstrapping (`app.py`)**: Because Vercel wipes the `/tmp` folder whenever a serverless function goes idle (cold starts), I updated `app.py` to automatically run the `init_db` script. This guarantees that your Master Secret Keys and `admin` user are recreated instantly and deterministically if the server restarts!

---

## Deployment Steps

### Method 1: Deploying via GitHub (Recommended)
1. Push your local `HyperTrust` directory to a new repository on **GitHub**.
2. Go to [Vercel.com](https://vercel.com/) and log in.
3. Click **Add New** > **Project**.
4. Import your newly created GitHub repository.
5. Expand the **Environment Variables** section and add:
   - **Key**: `VERCEL`
   - **Value**: `1`
   - *(This is extremely important. It tells the app to use the `/tmp` routing for the database).*
6. Click **Deploy**. Vercel will install your `requirements.txt` and launch the app in seconds.

### Method 2: Deploying via Vercel CLI
If you prefer using the command line and you have the `vercel` CLI installed globally via npm:
1. Open your terminal in the `HyperTrust` directory.
2. Run the command:
   ```bash
   vercel
   ```
3. Follow the CLI prompts to link your project.
4. Once linked, go to your project dashboard on the Vercel website, add the `VERCEL=1` Environment Variable, and then run:
   ```bash
   vercel --prod
   ``` 

> [!NOTE] 
> Because of Vercel's serverless nature, any new users you manually add to the system will be wiped whenever the serverless function spins down (usually after 10-15 minutes of inactivity). The original `admin` user will perpetually be recreated. If you need permanent persistent storage, you can migrate from SQLite to **Vercel Postgres** in the future!
