<script>
import { VcDonut } from "vue-css-donut-chart";
import axios from "axios";
import commonMixins from "../../mixins/CommonMixins";

export default {
	components: {
		VcDonut,
	},

	mixins: [commonMixins],

	props: {
		message: {
			type: Object,
			default: () => ({}),
		},
	},

	emits: ["setSpamFilterScore", "setBadgeStyle"],

	data() {
		return {
			error: false,
			check: false,
		};
	},

	computed: {
		threshold() {
			return this.check && this.check.Threshold ? this.check.Threshold : 5;
		},

		graphSections() {
			const score = this.check.Score;
			let p = Math.round((score / this.threshold) * 100);
			if (p > 100) {
				p = 100;
			} else if (p < 0) {
				p = 0;
			}

			let c = "#ffc107";
			if (this.check.IsSpam) {
				c = "#dc3545";
			}

			return [
				{
					label: score + " / " + this.threshold,
					value: p,
					color: c,
				},
			];
		},

		scoreColor() {
			return this.graphSections[0].color;
		},
	},

	watch: {
		message: {
			handler() {
				this.$emit("setSpamFilterScore", false);
				this.doCheck();
			},
			deep: true,
		},
	},

	mounted() {
		this.doCheck();
	},

	methods: {
		doCheck() {
			this.check = false;

			// ignore any error, do not show loader
			axios
				.get(this.resolve("/api/v1/message/" + this.message.ID + "/spam-check"), null)
				.then((result) => {
					this.check = result.data;
					this.error = false;
					this.setIcons();
				})
				.catch((error) => {
					// handle error
					if (error.response && error.response.data) {
						// The request was made and the server responded with a status code
						// that falls out of the range of 2xx
						if (error.response.data.Error) {
							this.error = error.response.data.Error;
						} else {
							this.error = error.response.data;
						}
					} else if (error.request) {
						// The request was made but no response was received
						// `error.request` is an instance of XMLHttpRequest in the browser and an instance of
						// http.ClientRequest in node.js
						this.error = "Error sending data to the server. Please try again.";
					} else {
						// Something happened in setting up the request that triggered an Error
						this.error = error.message;
					}
				});
		},

		badgeStyle(ignorePadding = false) {
			let badgeStyle = "bg-success";
			if (this.error) {
				badgeStyle = "bg-warning text-primary";
			} else if (this.check.IsSpam) {
				badgeStyle = "bg-danger";
			} else if (this.check.Score >= this.threshold - 1) {
				badgeStyle = "bg-warning text-primary";
			}

			if (!ignorePadding && String(this.check.Score).includes(".")) {
				badgeStyle += " p-1";
			}

			return badgeStyle;
		},

		setIcons() {
			let score = this.check.Score;
			if (this.error) {
				score = "!";
			}
			const badgeStyle = this.badgeStyle();
			this.$emit("setBadgeStyle", badgeStyle);
			this.$emit("setSpamFilterScore", score);
		},
	},
};
</script>

<template>
	<div class="row mb-3 w-100 align-items-center">
		<div class="col">
			<h4 class="mb-0">Spam Filter</h4>
		</div>
		<div class="col-auto">
			<button class="btn btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#AboutSpamFilter">
				<i class="bi bi-info-circle-fill"></i>
				Help
			</button>
		</div>
	</div>

	<template v-if="error">
		<p>Your message could not be checked</p>
		<div class="alert alert-warning">
			{{ error }}
		</div>
	</template>

	<template v-else-if="check">
		<div class="row w-100 mt-5">
			<div class="col-xl-5 mb-2">
				<vc-donut
					:sections="graphSections"
					background="var(--bs-body-bg)"
					:size="230"
					unit="px"
					:thickness="20"
					:total="100"
					:start-angle="270"
					:auto-adjust-text-size="true"
					foreground="#198754"
				>
					<h2 class="m-0" :class="scoreColor">{{ check.Score }} / {{ threshold }}</h2>
					<div class="text-body mt-2">
						<span v-if="check.IsSpam" class="text-white badge rounded-pill bg-danger p-2">Spam</span>
						<span v-else class="badge rounded-pill p-2" :class="badgeStyle()">Not spam</span>
					</div>
				</vc-donut>
			</div>
			<div class="col-xl-7">
				<div class="row w-100 py-2 border-bottom">
					<div class="col-2 col-lg-1">
						<strong>Score</strong>
					</div>
					<div class="col-10 col-lg-5">
						<strong>Rule <span class="d-none d-lg-inline">name</span></strong>
					</div>
					<div class="col-auto d-none d-lg-block">
						<strong>Description</strong>
					</div>
				</div>

				<div v-if="check.Rules.length == 0" class="row w-100 py-2 border-bottom small">
					<div class="col text-body-secondary">No rules triggered.</div>
				</div>

				<div v-for="r in check.Rules" :key="'rule_' + r.Name" class="row w-100 py-2 border-bottom small">
					<div class="col-2 col-lg-1">
						{{ r.Score }}
					</div>
					<div class="col-10 col-lg-5">
						{{ r.Name }}
						<span v-if="!r.Builtin" class="badge rounded-pill bg-info text-dark ms-1">custom</span>
					</div>
					<div class="col-auto col-lg-6 mt-2 mt-lg-0 offset-2 offset-lg-0">
						{{ r.Description }}
					</div>
				</div>
			</div>
		</div>
	</template>

	<div
		id="AboutSpamFilter"
		class="modal fade"
		tabindex="-1"
		aria-labelledby="AboutSpamFilterLabel"
		aria-hidden="true"
	>
		<div class="modal-dialog modal-lg modal-dialog-scrollable">
			<div class="modal-content">
				<div class="modal-header">
					<h1 id="AboutSpamFilterLabel" class="modal-title fs-5">About the Spam Filter</h1>
					<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
				</div>
				<div class="modal-body">
					<div id="SpamFilterAboutAccordion" class="accordion">
						<div class="accordion-item">
							<h2 class="accordion-header">
								<button
									class="accordion-button collapsed"
									type="button"
									data-bs-toggle="collapse"
									data-bs-target="#sf-col1"
									aria-expanded="false"
									aria-controls="sf-col1"
								>
									What is the Spam Filter?
								</button>
							</h2>
							<div
								id="sf-col1"
								class="accordion-collapse collapse"
								data-bs-parent="#SpamFilterAboutAccordion"
							>
								<div class="accordion-body">
									<p>
										Mailpit includes a built-in, heuristic spam filter that runs entirely locally —
										no external SpamAssassin server or third-party service is required. Every
										incoming message is checked against a set of preset rules covering common spam
										and phishing characteristics such as forged sender names, phishing forms and
										password inputs, executable attachments, suspicious links and typical spam
										phrases.
									</p>
									<p>
										Messages reaching the spam threshold are automatically tagged (by default with
										the <code>spam</code> tag) so you can find them using the tags or search. The
										filter never blocks or deletes any mail.
									</p>
								</div>
							</div>
						</div>
						<div class="accordion-item">
							<h2 class="accordion-header">
								<button
									class="accordion-button collapsed"
									type="button"
									data-bs-toggle="collapse"
									data-bs-target="#sf-col2"
									aria-expanded="false"
									aria-controls="sf-col2"
								>
									How does the point system work?
								</button>
							</h2>
							<div
								id="sf-col2"
								class="accordion-collapse collapse"
								data-bs-parent="#SpamFilterAboutAccordion"
							>
								<div class="accordion-body">
									<p>
										Each triggered rule adds (or subtracts) points. The default spam threshold is
										<code>5.0</code>: any score below 5 is considered ham (not spam), and a score of
										5 or above is considered spam. The threshold and tag name can be customised via
										the spam filter configuration file.
									</p>
								</div>
							</div>
						</div>
						<div class="accordion-item">
							<h2 class="accordion-header">
								<button
									class="accordion-button collapsed"
									type="button"
									data-bs-toggle="collapse"
									data-bs-target="#sf-col3"
									aria-expanded="false"
									aria-controls="sf-col3"
								>
									Can I add my own rules?
								</button>
							</h2>
							<div
								id="sf-col3"
								class="accordion-collapse collapse"
								data-bs-parent="#SpamFilterAboutAccordion"
							>
								<div class="accordion-body">
									<p>
										Yes. Load a YAML configuration file with
										<code>--spam-filter-config</code> (or the
										<code>MP_SPAM_FILTER_CONFIG</code> environment variable) to add your own
										regular-expression rules, adjust the threshold and tag, disable built-in rules,
										or define sender allow/block lists. Rules marked
										<span class="badge rounded-pill bg-info text-dark">custom</span> in the list
										above come from your configuration.
									</p>
									<p>The filter can be disabled entirely with <code>--disable-spam-filter</code>.</p>
								</div>
							</div>
						</div>
					</div>
				</div>
				<div class="modal-footer">
					<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
				</div>
			</div>
		</div>
	</div>
</template>
