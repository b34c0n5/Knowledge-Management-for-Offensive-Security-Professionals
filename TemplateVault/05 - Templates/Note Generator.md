<%*
////// Prompt user for note title 
// returns $title
var title = tp.file.title;
// No empty titles or untitled in file name allowed.
if (title === null || title.includes('Untitled') || title === "" ){
	var title = await tp.system.prompt("Note Title:");
	await tp.file.rename(title);
} else {
	console.log(`Title: "${title}" is valid`);
}


////// Prompt user for note type
// returns $type
var type = await tp.system.suggester( (item) => item, [
	"Cheatsheet Note",
	"Documentation Note",
	"Technique Note", 
	"Write Up Note"
] );
console.log(`Select a note type: "${type}" is valid`);


//// Retrieve all necessary files (TO-DO, turn this into a function so only files that are needed get retrieved)
body = await tp.file.include("[[0505 - Body]]");
challenges = await tp.file.include("[[0506 - Body_Challenges]]");
mitre = await tp.file.include("[[0507 - Body_MITRE]]");
steps = await tp.file.include("[[0508 - Body_Steps]]");
opsec = await tp.file.include("[[0509 - Body_OPSEC]]");
code = await tp.file.include("[[0510 - Body_Code]]");
examples = await tp.file.include("[[0511 - Body_Examples]]");
install = await tp.file.include("[[0512 - Body_Install]]");
resources = await tp.file.include("[[0513 - Resources]]");


////// Select correct correct header and options based on $type
// returns $header
switch (type) {
    case "Cheatsheet Note":
        header = await tp.file.include("[[0501 - Header_CheatSheet]]");
        options = (mitre + examples + resources);
        break;
    case "Documentation Note":
        header = await tp.file.include("[[0503 - Header_Documentation]]");
        options = (install + resources);
        break;
    case "Technique Note":
        header = await tp.file.include("[[0502 - Header_Technique]]");
        options = (mitre + challenges + steps + opsec + code + examples + resources);
        break;
    // write up note (more complex)
    case "Write Up Note":
	    header = await tp.file.include("[[0504 - Header_Writeup]]");
		var type = await tp.system.suggester( (item) => item, [
			"Progress Tracker Note",
			"Discovery Note",
			"Host Note", 
			"Domain Note",
			"Payload Delivery Note"
		] );
		switch (type) {
			case "Progress Tracker Note":
				progressTracker= await tp.file.include("[[0614 - Progress Tracker Template]]");
				options = progressTracker;
				var note = (header + options);
				console.log(`Note defined. All ready`);
				return note;
				break;
			case "Discovery Note":
				discovery = await tp.file.include("[[0615 - External Discovery Template]]");
				options = discovery;
				var note = (header + options);
				console.log(`Note defined. All ready`);
				return note;
				break;
			case "Host Note":
				host = await tp.file.include("[[0616 - Host Discovery + Privilege Escalation Template]]");
				options = host;
				var note = (header + options);
				console.log(`Note defined. All ready`);
				return note;
				break;
			case "Domain Note":
				domain = await tp.file.include("[[0617 - Domain Discovery + Privilege Escalation + Lateral Movement Template]]");
				options = domain;
				var note = (header + options);
				console.log(`Note defined. All ready`);
				return note;
				break;
			case "Payload Delivery Note":
				payloadDelivery = await tp.file.include("[[0618 - Payload Delivery Commands Template]]");
				options = payloadDelivery;
				var note = (header + options);
				console.log(`Note defined. All ready`);
				return note;
				break;
			default:
		        console.log("Invalid write up note type.");
		}
        break;
    default:
        console.log("Invalid note type.");
}
console.log(`Header and options selected.`);


////// Builds note using $header, main body and options
var note = (header + body + options);
console.log(`Note defined. All ready`);
return note;
%>

