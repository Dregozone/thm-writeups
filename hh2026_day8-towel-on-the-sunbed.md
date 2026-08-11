# Hacker Holidays (Day 8) - Towel On The Sunbed

## Room details

| Key | Value |
| ---- | ---- |
| Room name | Towel On The Sunbed |
| Room link | [https://tryhackme.com/room/hh-towelonthesunbed-61271709](https://tryhackme.com/room/hh-towelonthesunbed-61271709) |
| Difficulty | Medium |
| Date started | 11 Aug 2026 |
| Date completed | 11 Aug 2026 |
| Tags | web, burp |

## tl;dr Non-technical explanation

The app has a daily reward feature that can be triggered many times side-by-side to reward the user more times than intended. 

I captured the claim request and replayed several copies at the same time, which let me stack up enough points to unlock the prize in one sitting instead of waiting 3 days.

A lock should be placed at time of collection so that only the first of any simultaneous claims counts.


## Scenario

There is a web app on port 3000 (Provided by room details), loading this in a browser takes to a login screen. Register an account to see action to collect reward of 50 points once per 24 hours. There is a prize at 150 points, we want to activate the prize (flag) before 3 days pass.

## Reconnaissance (What I checked for and why)

- I registered an account to see what a non-privileged user may see/do, and how the app is designed to be operated by the developers.
- Clicking to receive the daily reward removes the ability to click it again until the timer runs down. It also rewards 50 points in the cumulative point score at the top of the page. I did this to see how the operation should function correctly and to find the win-condition: the cumulative score increases by more than 50 at a time.


## The vuln

I was able to queue up multiple requests and fire them off simultaneously to receive duplicated daily rewards.

Using TOCTOU (Time of check to Time of use), we can request many checks that will all pass as being run simultaneously to then queue up a larger number of actions that rely on the check passing, this exploits a race condition when the check and the reward aren't performed atomically.


## Exploitation steps

1. Open burp suite and go to "Proxy" tab
2. Open burp browser, enabling run in sandbox mode as required
3. Login or register a normal account, do not redeem points at this stage
4. Enable proxy intercept mode
5. Click to receive daily reward - This is caught by the burp intercept and can be examined
6. Right click and send the intercepted request to "Repeater"
7. View repeater tab of burp suite, right click and add to a new group
8. Right click and Duplicate the request 7 more times (We only need 3 but add a few extras in case some requests fail to reach the target)
9. Select in the dropdown to "Send group in parallel" (Bottom option) with last byte sync'd - This ensures that all requests land as close to the same time as possible, maximising the chance to exploit the race condition 


## Remediation

Enforce the once-per-24h rule atomically at the database level with a UNIQUE constraint on (user, claim date), so that concurrent duplicate claims are rejected rather than all passing an initial check. 

These can be wrapped in a transaction in the app layer to perform corrective actions as required.


### Laravel/PHP solution

(Below) Migration that enforces uniqueness per user per date
```php
Schema::create('reward_claims', function (Blueprint $table) {
    $table->id();
    $table->foreignId('user_id')->constrained();
    $table->date('claim_date');
    $table->timestamps();

    $table->unique(['user_id', 'claim_date']); // the gatekeeper
});
```

(Below) App logic that only performs the increment after the unique constraint passes, otherwise catches for graceful failure
```php
use Illuminate\Support\Facades\DB;
use Illuminate\Database\UniqueConstraintViolationException;

public function claimDailyReward(User $user): bool
{
    try {
        DB::transaction(function () use ($user) {
            // Insert the constrained row FIRST. The DB's unique index
            // decides the winner: exactly one concurrent request lands
            // this row, every other one throws here.
            RewardClaim::create([
                'user_id'    => $user->id,
                'claim_date' => today(),
            ]);

            // Only reached by the winning request.
            $user->increment('points', 50);
        });
    } catch (UniqueConstraintViolationException $e) {
        // A concurrent (or later) request already claimed today. No reward.
        return false;
    }

    return true;
}
```

Depending on the business logic, the requirement could be: Once per calendar date or once per 24 hours, the above snippets solve for once per calendar date but we can also allow for once per 24 hours with a check for `last_claim_at < now()->subDay()`, and performing an `UPDATE ... WHERE ...` atomic query within Laravel:

```php
$claimed = DB::table('users')
    ->where('id', $user->id)
    ->where(function ($q) {
        $q->whereNull('last_claim_at')
          ->orWhere('last_claim_at', '<=', now()->subDay());
    })
    ->update([
        'last_claim_at' => now(),
        'points'        => DB::raw('points + 50'),
    ]);

if ($claimed === 0) {
    return false; // 24h not elapsed, OR a concurrent request already claimed
}
```


## Lessons learned/Key takeaways

**Atomic** - The idea that an operation either happens completely or not at all

**TOCTOU (Time of check to time of use)** - Checking whether a condition is true, then performing the action opens vulnerability to send many requests simultaneously; most or all will pass the check, then continue to perform the secondary action many times.
