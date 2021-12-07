docs: docs/sniffglue.1

docs/%.1: docs/%.1.scd
	scdoc > $@ < $^

.PHONEY: docs
