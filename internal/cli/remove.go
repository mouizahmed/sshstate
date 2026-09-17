package cli

import (
	"context"

	"github.com/mouizahmed/sshstate/internal/control"
)

func runRemove(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "remove")
	yes := fs.Bool("yes", false, "answer yes to the confirmation prompt")
	positional, rest := splitPositional(args, 1)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	positional = append(positional, fs.Args()...)
	if len(positional) != 1 {
		return usageError("remove")
	}
	hosts, err := env.Client().Hosts(ctx)
	if err != nil {
		return env.hint(err)
	}
	target, err := resolveHost(hosts, positional[0])
	if err != nil {
		return err
	}
	if !*yes {
		env.printf("%s -> %s@%s:%d\n", target.Alias, target.User, target.HostName, target.Port)
		ok, err := env.confirm("Remove this host from the vault?")
		if err != nil {
			return withBypass(err, "--yes")
		}
		if !ok {
			env.printf("Nothing changed.\n")
			return nil
		}
	}
	res, err := env.Client().RemoveHost(ctx, control.RemoveRequest{RecordID: target.RecordID})
	if err != nil {
		return env.hint(err)
	}
	env.printf("Removed host %s.\n", res.Subject)
	env.printf("Keys it referenced stay in the vault; see: sshstate keys\n")
	env.printf("\nConfig regenerated at %s\n", env.Layout.Config())
	return nil
}

func runRemoveKey(ctx context.Context, env *Env, args []string) error {
	fs := newFlagSet(env, "remove-key")
	yes := fs.Bool("yes", false, "answer yes to the confirmation prompt")
	positional, rest := splitPositional(args, 1)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	positional = append(positional, fs.Args()...)
	if len(positional) != 1 {
		return usageError("remove-key")
	}
	keys, err := env.Client().Keys(ctx)
	if err != nil {
		return env.hint(err)
	}
	id, err := resolveKeyID(keys, positional[0])
	if err != nil {
		return err
	}
	var target *control.KeyResponse
	for i, k := range keys {
		if k.RecordID == id {
			target = &keys[i]
			break
		}
	}
	if !*yes {
		env.printf("%s %s", target.Algorithm, target.Fingerprint)
		if target.Comment != "" {
			env.printf("  %s", target.Comment)
		}
		env.printf("\n")
		env.warnf("The private key is destroyed with the record. Anything that still needs it\n")
		env.warnf("must be reimported from your own copy, which sshstate never touched.\n")
		ok, err := env.confirm("Remove this key from the vault?")
		if err != nil {
			return withBypass(err, "--yes")
		}
		if !ok {
			env.printf("Nothing changed.\n")
			return nil
		}
	}
	res, err := env.Client().RemoveKey(ctx, control.RemoveRequest{RecordID: id})
	if err != nil {
		return env.hint(err)
	}
	env.printf("Removed key %s.\n", res.Subject)
	return nil
}
